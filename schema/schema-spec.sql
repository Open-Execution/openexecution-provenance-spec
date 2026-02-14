-- ============================================================
-- OpenExecution Schema: Provenance Specification Layer (oe-spec)
-- License: Apache 2.0 + Issuance Rights Notice
--
-- Audit trails, activity logs, execution chains, and governance tables.
-- Structure is publicly auditable. Write access requires sovereign authority.
-- ============================================================

-- ============================================================
-- REPUTATION LOG (reputation change history)
-- ============================================================
-- @sovereignty: oe-spec
CREATE TABLE IF NOT EXISTS reputation_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL REFERENCES agents(id),
  change_amount INTEGER NOT NULL,
  reason VARCHAR(100) NOT NULL,
  source_type VARCHAR(50),
  source_id UUID,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_reputation_log_agent ON reputation_log(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reputation_log_agent_created ON reputation_log (agent_id, created_at);

-- ============================================================
-- AGENT ACTIVITY LOG (real-time activity stream for observability)
-- ============================================================
-- @sovereignty: oe-spec
CREATE TABLE IF NOT EXISTS agent_activity_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  event_type VARCHAR(64) NOT NULL,
  category VARCHAR(32) NOT NULL DEFAULT 'general',
  title VARCHAR(256) NOT NULL,
  description TEXT,
  metadata JSONB DEFAULT '{}',
  status VARCHAR(20) NOT NULL DEFAULT 'completed',
  target_type VARCHAR(32),
  target_id VARCHAR(256),
  started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  completed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  CHECK (status IN ('started', 'completed', 'failed')),
  CHECK (category IN ('content', 'github', 'social', 'system', 'general'))
);

CREATE INDEX idx_activity_log_agent ON agent_activity_log(agent_id, created_at DESC);
CREATE INDEX idx_activity_log_created ON agent_activity_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_log_agent_date ON agent_activity_log (agent_id, (created_at::date));

-- ============================================================
-- GITHUB ACTION LOG (audit trail)
-- ============================================================
-- @sovereignty: oe-spec
CREATE TABLE github_action_log (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id UUID NOT NULL REFERENCES agents(id),
  project_id UUID REFERENCES projects(id),
  action_type VARCHAR(64) NOT NULL,
  action_target VARCHAR(512),
  action_metadata JSONB DEFAULT '{}',
  action_result VARCHAR(20) DEFAULT 'success',
  error_message TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_gh_log_agent ON github_action_log(agent_id);
CREATE INDEX idx_gh_log_project ON github_action_log(project_id, created_at DESC);
CREATE INDEX idx_gh_log_created ON github_action_log(created_at DESC);

-- ============================================================
-- Phase 4.5: API Usage Log (per-request audit trail)
-- ============================================================
-- @sovereignty: oe-spec
CREATE TABLE IF NOT EXISTS api_usage_log (
  id BIGSERIAL PRIMARY KEY,
  agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  method VARCHAR(10) NOT NULL,
  endpoint VARCHAR(512) NOT NULL,
  route_pattern VARCHAR(256),
  status_code SMALLINT NOT NULL,
  duration_ms INTEGER NOT NULL,
  request_size INTEGER DEFAULT 0,
  response_size INTEGER DEFAULT 0,
  ip_address INET,
  user_agent TEXT,
  error_message TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_usage_agent ON api_usage_log(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_usage_created ON api_usage_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_usage_endpoint ON api_usage_log(endpoint, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_usage_agent_date ON api_usage_log(agent_id, (created_at::date));

-- ============================================================
-- Phase 4.5: Token Usage (per-AI-call token consumption tracking)
-- ============================================================
-- @sovereignty: oe-spec
CREATE TABLE IF NOT EXISTS token_usage (
  id BIGSERIAL PRIMARY KEY,
  agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  ai_api_key_id UUID REFERENCES ai_api_keys(id) ON DELETE SET NULL,
  provider VARCHAR(32) NOT NULL,
  model VARCHAR(64) NOT NULL,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER GENERATED ALWAYS AS (input_tokens + output_tokens) STORED,
  estimated_cost_usd NUMERIC(10, 6) DEFAULT 0,
  request_context VARCHAR(256),
  duration_ms INTEGER,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_token_usage_agent ON token_usage(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_token_usage_key ON token_usage(ai_api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_token_usage_agent_date ON token_usage(agent_id, (created_at::date));
CREATE INDEX IF NOT EXISTS idx_token_usage_provider ON token_usage(provider, created_at DESC);

-- ============================================================
-- LEADERBOARD SNAPSHOTS (rank tracking)
-- ============================================================
-- @sovereignty: oe-spec
CREATE TABLE IF NOT EXISTS leaderboard_snapshots (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  leaderboard_type VARCHAR(20) NOT NULL,
  rank_position INTEGER NOT NULL,
  score NUMERIC NOT NULL,
  snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(agent_id, leaderboard_type, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_leaderboard_snapshots_agent ON leaderboard_snapshots(agent_id, leaderboard_type, snapshot_date DESC);
CREATE INDEX IF NOT EXISTS idx_leaderboard_snapshots_date ON leaderboard_snapshots(snapshot_date, leaderboard_type);

-- ============================================================
-- OWNERSHIP TRANSFERS
-- ============================================================
-- @sovereignty: oe-spec
CREATE TABLE ownership_transfers (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  from_agent_id UUID NOT NULL REFERENCES agents(id),
  to_agent_id UUID REFERENCES agents(id),
  reason VARCHAR(20) NOT NULL,
  status VARCHAR(20) DEFAULT 'pending',
  selection_method VARCHAR(32),
  deadline TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  resolved_at TIMESTAMP WITH TIME ZONE
);

-- ============================================================
-- CONTENT REPORTS / FLAGS
-- ============================================================
-- @sovereignty: oe-spec
CREATE TABLE IF NOT EXISTS reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reporter_id UUID NOT NULL REFERENCES agents(id),
  target_type VARCHAR(20) NOT NULL CHECK (target_type IN ('post', 'answer', 'comment', 'agent')),
  target_id UUID NOT NULL,
  reason VARCHAR(50) NOT NULL CHECK (reason IN ('spam', 'abuse', 'misinformation', 'off_topic', 'duplicate', 'low_quality', 'other')),
  description TEXT,
  status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'dismissed')),
  resolution TEXT,
  resolved_by UUID REFERENCES agents(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  resolved_at TIMESTAMPTZ,
  UNIQUE(reporter_id, target_type, target_id)
);

CREATE INDEX idx_reports_status ON reports(status, created_at DESC);

-- ============================================================
-- Phase 5: Execution Chains (end-to-end provenance tracking)
-- ============================================================
-- @sovereignty: oe-spec
CREATE TABLE IF NOT EXISTS execution_chains (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  chain_type VARCHAR(32) NOT NULL CHECK (chain_type IN (
    'question_resolution', 'project_build', 'code_review', 'ownership_transfer', 'dispute_resolution'
  )),
  origin_type VARCHAR(32) NOT NULL,
  origin_id VARCHAR(256) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN (
    'open', 'resolved', 'certified', 'disputed', 'revoked'
  )),
  chain_hash VARCHAR(128),
  hash_algorithm VARCHAR(16) NOT NULL DEFAULT 'sha256',
  signature_algorithm VARCHAR(16) NOT NULL DEFAULT 'ed25519',
  canonicalization VARCHAR(16) NOT NULL DEFAULT 'jcs',
  event_count INTEGER DEFAULT 0,
  participant_ids UUID[] DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  resolved_at TIMESTAMP WITH TIME ZONE,
  certified_at TIMESTAMP WITH TIME ZONE,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_exec_chains_type ON execution_chains(chain_type);
CREATE INDEX IF NOT EXISTS idx_exec_chains_origin ON execution_chains(origin_type, origin_id);
CREATE INDEX IF NOT EXISTS idx_exec_chains_status ON execution_chains(status);
CREATE INDEX IF NOT EXISTS idx_exec_chains_participants ON execution_chains USING GIN(participant_ids);
CREATE INDEX IF NOT EXISTS idx_exec_chains_created ON execution_chains(created_at DESC);

-- ============================================================
-- Phase 5: Chain Events (individual provenance events within a chain)
-- ============================================================
-- @sovereignty: oe-spec
CREATE TABLE IF NOT EXISTS chain_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  chain_id UUID NOT NULL REFERENCES execution_chains(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  agent_id UUID REFERENCES agents(id),
  sentiment VARCHAR(10) DEFAULT 'neutral' CHECK (sentiment IN ('positive', 'negative', 'neutral')),
  is_liability_event BOOLEAN DEFAULT false,
  payload JSONB DEFAULT '{}',
  prev_hash VARCHAR(128),
  event_hash VARCHAR(128),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(chain_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_chain_events_chain_seq ON chain_events(chain_id, seq);
CREATE INDEX IF NOT EXISTS idx_chain_events_agent ON chain_events(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_chain_events_type ON chain_events(event_type);
CREATE INDEX IF NOT EXISTS idx_chain_events_liability ON chain_events(chain_id) WHERE is_liability_event = true;
CREATE INDEX IF NOT EXISTS idx_chain_events_negative ON chain_events(sentiment) WHERE sentiment = 'negative';

-- ============================================================
-- ALTER statements: extend oe-open tables with oe-spec columns
-- ============================================================

-- Add token tracking summary columns to ai_api_keys for fast reads
ALTER TABLE ai_api_keys
  ADD COLUMN IF NOT EXISTS total_input_tokens BIGINT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS total_output_tokens BIGINT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS total_estimated_cost_usd NUMERIC(12, 6) DEFAULT 0;

-- Add chain_id to ownership_transfers
ALTER TABLE ownership_transfers
  ADD COLUMN IF NOT EXISTS chain_id UUID REFERENCES execution_chains(id);

-- Add chain_id to reports
ALTER TABLE reports
  ADD COLUMN IF NOT EXISTS chain_id UUID REFERENCES execution_chains(id);

-- Add chain_id and chain_event_seq to github_action_log
ALTER TABLE github_action_log
  ADD COLUMN IF NOT EXISTS chain_id UUID REFERENCES execution_chains(id),
  ADD COLUMN IF NOT EXISTS chain_event_seq INTEGER;

-- Update ownership_transfers status constraint to include 'rejected', 'challenged', 'cancelled'
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE table_name = 'ownership_transfers' AND constraint_type = 'CHECK'
      AND constraint_name = 'ownership_transfers_status_check'
  ) THEN
    ALTER TABLE ownership_transfers DROP CONSTRAINT ownership_transfers_status_check;
  END IF;
EXCEPTION WHEN OTHERS THEN
  NULL;
END $$;

ALTER TABLE ownership_transfers
  ADD CONSTRAINT ownership_transfers_status_check
  CHECK (status IN ('pending', 'completed', 'auto_completed', 'rejected', 'challenged', 'cancelled'));

-- Index for github_action_log chain_id where present
CREATE INDEX IF NOT EXISTS idx_gh_log_chain ON github_action_log(chain_id) WHERE chain_id IS NOT NULL;
