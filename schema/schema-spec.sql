-- ============================================================
-- OpenExecution Provenance Specification Schema
-- Version: 2.0.0
-- License: Apache 2.0 + Issuance Rights Notice
--
-- This schema defines the provenance-layer tables only.
-- It depends on platform-layer tables (users, platform_connections)
-- which are defined in the platform repository.
--
-- Tables:
--   execution_chains       — Hash-linked event chains per monitored resource
--   chain_events           — Individual tamper-evident events (immutable)
--   provenance_certificates — Signed attestations (court-ready evidence)
--   event_correlations     — Cross-stream corroboration results
--   algorithm_change_log   — Audit trail for crypto preference changes
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- EXECUTION CHAINS
-- ============================================================
CREATE TABLE execution_chains (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL,    -- references users(id)
  resource_id UUID,         -- references tracked_resources(id)
  chain_type VARCHAR(32) NOT NULL CHECK (chain_type IN (
    'resource_audit',       -- auto-created per monitored resource
    'manual',               -- user-created for custom workflows
    'incident_response',    -- tracking an incident
    'compliance_report'     -- compliance audit trail
  )),
  origin_type VARCHAR(32) NOT NULL,   -- platform name or 'manual'
  origin_id VARCHAR(256) NOT NULL,    -- resource identifier
  status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN (
    'open', 'resolved', 'certified', 'revoked'
  )),
  protocol_version VARCHAR(32) NOT NULL DEFAULT 'oe-provenance:1.0-alpha',
  chain_hash VARCHAR(128),
  hash_algorithm VARCHAR(16) NOT NULL DEFAULT 'sha256',
  signature_algorithm VARCHAR(16) NOT NULL DEFAULT 'ed25519',
  canonicalization VARCHAR(16) NOT NULL DEFAULT 'jcs',
  event_count INTEGER DEFAULT 0,
  -- Chain lineage (algorithm change supersession)
  predecessor_chain_id UUID REFERENCES execution_chains(id),
  successor_chain_id UUID REFERENCES execution_chains(id),
  superseded_at TIMESTAMPTZ,
  supersession_reason VARCHAR(64),
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  resolved_at TIMESTAMPTZ,
  certified_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_chains_user ON execution_chains(user_id);
CREATE INDEX idx_chains_type ON execution_chains(chain_type);
CREATE INDEX idx_chains_origin ON execution_chains(origin_type, origin_id);
CREATE INDEX idx_chains_status ON execution_chains(status);
CREATE INDEX idx_chains_created ON execution_chains(created_at DESC);
CREATE INDEX idx_chains_predecessor ON execution_chains(predecessor_chain_id) WHERE predecessor_chain_id IS NOT NULL;
CREATE INDEX idx_chains_successor ON execution_chains(successor_chain_id) WHERE successor_chain_id IS NOT NULL;
CREATE INDEX idx_chains_resource ON execution_chains(resource_id) WHERE resource_id IS NOT NULL;

-- ============================================================
-- ALGORITHM CHANGE LOG
-- ============================================================
CREATE TABLE algorithm_change_log (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL,    -- references users(id)
  previous_hash_algorithm VARCHAR(16) NOT NULL,
  previous_signature_algorithm VARCHAR(16) NOT NULL,
  new_hash_algorithm VARCHAR(16) NOT NULL,
  new_signature_algorithm VARCHAR(16) NOT NULL,
  chains_affected INTEGER NOT NULL DEFAULT 0,
  chains_superseded UUID[] DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_algo_change_user ON algorithm_change_log(user_id, created_at DESC);

-- ============================================================
-- CHAIN EVENTS (immutable provenance events)
-- ============================================================
CREATE TABLE chain_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  chain_id UUID NOT NULL REFERENCES execution_chains(id) ON DELETE RESTRICT,
  seq INTEGER NOT NULL,
  event_type VARCHAR(64) NOT NULL,

  -- Actor identity comes from the external platform, NOT from OE
  actor_id VARCHAR(512),              -- GitHub username, Notion user ID, etc.
  actor_type VARCHAR(64),             -- human, bot, app, service, unknown

  sentiment VARCHAR(10) DEFAULT 'neutral' CHECK (sentiment IN ('positive', 'negative', 'neutral')),
  is_liability_event BOOLEAN DEFAULT false,
  payload JSONB DEFAULT '{}',
  prev_hash VARCHAR(128),
  event_hash VARCHAR(128),
  payload_canonical_hash VARCHAR(128),

  -- Source tier: which data stream produced this event?
  attestation_source VARCHAR(20) NOT NULL DEFAULT 'platform_verified'
    CHECK (attestation_source IN ('platform_verified', 'agent_reported', 'cross_verified', 'gateway_observed')),

  -- AI tool attribution (set by adapter detection or MCP proxy)
  ai_tool VARCHAR(32),             -- github_copilot, claude_code, devin, cursor, amazon_q, gemini_code_assist, mcp_proxy
  ai_confidence VARCHAR(16),       -- definitive, verified, probable

  -- Cross-stream correlation pointer (mutable — set by correlation engine post-insert)
  correlation_id UUID REFERENCES chain_events(id),

  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(chain_id, seq)
);

CREATE INDEX idx_chain_events_chain_seq ON chain_events(chain_id, seq);
CREATE INDEX idx_chain_events_type ON chain_events(event_type);
CREATE INDEX idx_chain_events_ai_tool ON chain_events(ai_tool) WHERE ai_tool IS NOT NULL;
CREATE INDEX idx_chain_events_actor ON chain_events(actor_id) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_chain_events_liability ON chain_events(chain_id) WHERE is_liability_event = true;
CREATE INDEX idx_chain_events_attestation ON chain_events(attestation_source);
CREATE INDEX idx_chain_events_correlation ON chain_events(correlation_id) WHERE correlation_id IS NOT NULL;
CREATE INDEX idx_chain_events_chain_attestation_time ON chain_events(chain_id, attestation_source, created_at);

-- ============================================================
-- EVENT CORRELATIONS (cross-stream corroboration results)
-- ============================================================
CREATE TABLE event_correlations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_event_id UUID NOT NULL REFERENCES chain_events(id),
  platform_event_id UUID NOT NULL REFERENCES chain_events(id),
  correlation_type VARCHAR(20) NOT NULL CHECK (correlation_type IN (
    'exact', 'temporal', 'inferred'
  )),
  confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
  match_key VARCHAR(512),
  match_details JSONB DEFAULT '{}',
  corroboration_status VARCHAR(20) NOT NULL DEFAULT 'matched'
    CHECK (corroboration_status IN (
      'matched', 'divergent', 'agent_only', 'platform_only'
    )),
  created_by VARCHAR(32) NOT NULL DEFAULT 'correlation_engine',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(agent_event_id, platform_event_id)
);

CREATE INDEX idx_correlations_agent ON event_correlations(agent_event_id);
CREATE INDEX idx_correlations_platform ON event_correlations(platform_event_id);
CREATE INDEX idx_correlations_status ON event_correlations(corroboration_status);

-- ============================================================
-- PROVENANCE CERTIFICATES
-- ============================================================
CREATE TABLE provenance_certificates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  chain_id UUID NOT NULL REFERENCES execution_chains(id) UNIQUE,
  user_id UUID NOT NULL,    -- references users(id)
  artifact_type VARCHAR(64) NOT NULL,
  artifact_ref VARCHAR(512) NOT NULL,
  artifact_title VARCHAR(500),
  certificate_data JSONB,
  chain_hash VARCHAR(128),
  certificate_signature VARCHAR(8192),
  signature_algorithm VARCHAR(16) NOT NULL DEFAULT 'ed25519',
  public_key_fingerprint VARCHAR(64),
  hash_algorithm VARCHAR(16) NOT NULL DEFAULT 'sha256',
  canonicalization VARCHAR(16) NOT NULL DEFAULT 'jcs',
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'superseded')),
  revocation_reason TEXT,
  revoked_at TIMESTAMPTZ,
  superseded_by UUID REFERENCES provenance_certificates(id),
  issued_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_prov_certs_chain ON provenance_certificates(chain_id);
CREATE INDEX idx_prov_certs_user ON provenance_certificates(user_id);
CREATE INDEX idx_prov_certs_artifact ON provenance_certificates(artifact_type, artifact_ref);
CREATE INDEX idx_prov_certs_status ON provenance_certificates(status);
