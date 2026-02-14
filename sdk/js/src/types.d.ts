import { KeyObject } from 'crypto';

// ---------------------------------------------------------------------------
// Algorithm types
// ---------------------------------------------------------------------------

export type HashAlgorithm = 'sha256' | 'sha384' | 'sha512' | 'sha3-256' | 'sha3-384' | 'sha3-512';
export type SignatureAlgorithm = 'ed25519' | 'ed448' | 'ecdsa-p256' | 'ecdsa-p384' | 'ecdsa-p521';
export type CanonicalizationMethod = 'jcs';

export type PublicKeyInput = string | Buffer | KeyObject;

// ---------------------------------------------------------------------------
// Chain & certificate types
// ---------------------------------------------------------------------------

export interface ChainEvent {
  seq: number;
  event_type: string;
  agent_id: string | null;
  created_at: string;
  payload: Record<string, unknown>;
  prev_hash: string;
  event_hash: string;
}

export interface ChainData {
  id: string;
  events: ChainEvent[];
  hash_algorithm?: HashAlgorithm;
  signature_algorithm?: SignatureAlgorithm;
  canonicalization?: CanonicalizationMethod;
}

export interface Certificate {
  id: string;
  chain_id: string;
  chain_hash?: string;
  artifact_type: string;
  artifact_ref: string;
  status: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Verification results
// ---------------------------------------------------------------------------

export interface VerificationResult {
  valid: boolean;
  signature_valid: boolean;
  chain_hash_valid: boolean;
  certificate: {
    id: string;
    chain_id: string;
    artifact_type: string;
    artifact_ref: string;
    status: string;
  };
  chain: {
    id: string;
    chain_type: string;
    status: string;
  };
  integrity: ChainIntegrityResult;
}

export interface ChainIntegrityResult {
  is_valid: boolean;
  event_count: number;
  errors: string[];
}

export interface BundleVerificationResult {
  valid: boolean;
  certificate_signature_valid: boolean;
  chain_integrity: ChainIntegrityResult | null;
  chain_hash_valid: boolean;
  attestation_results?: AttestationResult[];
  errors: string[];
}

// ---------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------

export interface VerificationBundle {
  certificate: Certificate;
  certificate_signature: string;
  chain: ChainData;
  public_key: string;
  attestations?: Attestation[];
}

// ---------------------------------------------------------------------------
// Extension attestations
// ---------------------------------------------------------------------------

export interface ContentIntegrityAttestation {
  type: 'ContentIntegrity';
  root_hash?: string;
  merkle_root?: string;
  leaves?: string[];
  leaf_hashes?: string[];
  proof?: string[];
  hash_algorithm?: string;
}

export interface TimestampAttestation {
  type: 'Timestamp';
  /** SDK format */
  timestamp?: string;
  hash?: string;
  signed_timestamp?: string;
  /** Backend format */
  anchored_at?: string;
  anchor_hash?: string;
  head_hash?: string;
  chain_id?: string;
}

export interface BlockchainAttestation {
  type: 'Blockchain';
  tx_hash: string;
  /** SDK format */
  chain_hash?: string;
  /** Backend format */
  head_hash?: string;
  chain_id?: string;
  network?: string;
  block_number?: number;
}

export type Attestation =
  | ContentIntegrityAttestation
  | TimestampAttestation
  | BlockchainAttestation;

export interface AttestationVerificationOptions {
  publicKey?: PublicKeyInput;
  hashAlgorithm?: HashAlgorithm;
  signatureAlgorithm?: SignatureAlgorithm;
  expectedChainHash?: string;
}

export interface ContentIntegrityResult {
  valid: boolean;
  reason?: string;
  computed_root?: string;
  expected_root?: string;
  domain_separation?: 'rfc6962';
}

export interface TimestampResult {
  valid: boolean;
  reason?: string;
  hash_valid?: boolean;
  signature_valid?: boolean | null;
}

export interface BlockchainResult {
  valid: boolean;
  reason?: string;
  hash_match?: boolean | null;
  tx_hash?: string;
  network?: string;
}

export type AttestationResult =
  | ({ type: 'ContentIntegrity' } & ContentIntegrityResult)
  | ({ type: 'Timestamp' } & TimestampResult)
  | ({ type: 'Blockchain' } & BlockchainResult)
  | { type: string; valid: false; reason: string };

// ---------------------------------------------------------------------------
// Verifier class
// ---------------------------------------------------------------------------

export class OpenExecutionVerifier {
  constructor(options?: { apiUrl?: string });

  /** Online verification via API (backward-compatible). */
  verifyCertificate(certificateId: string): Promise<VerificationResult>;

  /** Offline Ed25519/Ed448/ECDSA signature verification over canonicalized data. */
  static verifySignatureOffline(
    certificateData: object,
    signatureHex: string,
    publicKey: PublicKeyInput,
    signatureAlgorithm?: SignatureAlgorithm,
  ): boolean;

  /** Verify chain event integrity (sequence, linkage, hashes). */
  static verifyChainIntegrity(
    events: ChainEvent[],
    options?: { hashAlgorithm?: HashAlgorithm; canonicalization?: CanonicalizationMethod },
  ): ChainIntegrityResult;

  /** Compute summary hash over all event hashes. */
  static computeChainHash(eventHashes: string[], hashAlgorithm?: HashAlgorithm): string;

  /** Verify a self-contained provenance bundle offline. */
  static verifyBundle(bundle: VerificationBundle): BundleVerificationResult;
}

// ---------------------------------------------------------------------------
// Standalone utility exports
// ---------------------------------------------------------------------------

export function canonicalize(obj: unknown): string;
export function hash(data: string | Buffer, algorithm?: HashAlgorithm): string;
export function verifySignature(
  data: string | Buffer,
  signatureHex: string,
  publicKey: PublicKeyInput,
  signatureAlgorithm?: SignatureAlgorithm,
): boolean;
export function verifyExtensionAttestation(
  attestation: Attestation,
  options?: AttestationVerificationOptions,
): AttestationResult;
export function verifyContentIntegrity(
  attestation: ContentIntegrityAttestation,
  hashAlgorithm?: HashAlgorithm,
): ContentIntegrityResult;
export function verifyTimestamp(
  attestation: TimestampAttestation,
  publicKey?: PublicKeyInput,
  hashAlgorithm?: HashAlgorithm,
  signatureAlgorithm?: SignatureAlgorithm,
): TimestampResult;
export function verifyBlockchain(
  attestation: BlockchainAttestation,
  expectedChainHash?: string,
): BlockchainResult;

export const HASH_MAP: Record<HashAlgorithm, string>;
export const SIGNATURE_ALGORITHMS: Record<SignatureAlgorithm, { hashArg: string | null }>;
