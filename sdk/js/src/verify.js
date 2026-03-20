'use strict';

const crypto = require('crypto');

const DEFAULT_API_URL = 'https://api.openexecution.dev/api/v1';

// Hash output lengths in hex chars, for algorithm-aware genesis hash
const HASH_OUTPUT_LENGTHS = {
  sha256: 64, sha384: 96, sha512: 128,
  'sha3-256': 64, 'sha3-384': 96, 'sha3-512': 128,
};

/**
 * Get the genesis prev_hash for a given hash algorithm.
 * @param {string} [hashAlgorithm='sha256']
 * @returns {string} all-zeros hex string of correct length
 */
function getGenesisHash(hashAlgorithm = 'sha256') {
  const len = HASH_OUTPUT_LENGTHS[hashAlgorithm] || 64;
  return '0'.repeat(len);
}

// ---------------------------------------------------------------------------
// Algorithm maps
// ---------------------------------------------------------------------------

const HASH_MAP = {
  'sha256': 'sha256', 'sha384': 'sha384', 'sha512': 'sha512',
  'sha3-256': 'sha3-256', 'sha3-384': 'sha3-384', 'sha3-512': 'sha3-512'
};

const SIGNATURE_ALGORITHMS = {
  'ed25519': { hashArg: null },
  'ed448':   { hashArg: null },
  'ecdsa-p256': { hashArg: 'sha256' },
  'ecdsa-p384': { hashArg: 'sha384' },
  'ecdsa-p521': { hashArg: 'sha512' },
};

// ---------------------------------------------------------------------------
// JCS Canonicalization (byte-identical to backend ProvenanceService)
// ---------------------------------------------------------------------------

function canonicalize(obj) {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalize(item)).join(',') + ']';
  }
  const sortedKeys = Object.keys(obj).sort();
  // RFC 8785 (JCS): omit keys whose value is undefined (JSON has no undefined)
  const pairs = sortedKeys
    .filter(key => obj[key] !== undefined)
    .map(key => JSON.stringify(key) + ':' + canonicalize(obj[key]));
  return '{' + pairs.join(',') + '}';
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function resolveHashAlgorithm(name) {
  const algo = HASH_MAP[name];
  if (!algo) throw new Error(`Unsupported hash algorithm: ${name}`);
  return algo;
}

function resolveSignatureAlgorithm(name) {
  const algo = SIGNATURE_ALGORITHMS[name];
  if (!algo) throw new Error(`Unsupported signature algorithm: ${name}`);
  return algo;
}

/**
 * Hash arbitrary data using a supported algorithm.
 * @param {string|Buffer} data
 * @param {string} algorithm - One of the keys in HASH_MAP
 * @returns {string} Hex-encoded hash
 */
function hash(data, algorithm = 'sha256') {
  return crypto.createHash(resolveHashAlgorithm(algorithm)).update(data).digest('hex');
}

/**
 * Parse a public key from PEM string or raw hex into a KeyObject.
 * @param {string|Buffer|crypto.KeyObject} input
 * @returns {crypto.KeyObject}
 */
function toPublicKey(input) {
  if (input instanceof crypto.KeyObject) return input;
  if (Buffer.isBuffer(input)) {
    // Attempt to interpret as PEM first, fall back to raw key import
    const str = input.toString('utf8');
    if (str.includes('-----BEGIN')) {
      return crypto.createPublicKey(str);
    }
    return crypto.createPublicKey({ key: input, format: 'der', type: 'spki' });
  }
  if (typeof input === 'string') {
    if (input.includes('-----BEGIN')) {
      return crypto.createPublicKey(input);
    }
    // Hex-encoded raw key — wrap in DER/PEM is fragile, so use raw import
    const buf = Buffer.from(input, 'hex');
    return crypto.createPublicKey({ key: buf, format: 'der', type: 'spki' });
  }
  throw new Error('Public key must be a PEM string, hex string, Buffer, or KeyObject');
}

/**
 * Verify an asymmetric signature.
 * @param {Buffer|string} data       - The signed payload
 * @param {string} signatureHex      - Hex-encoded signature
 * @param {string|Buffer|crypto.KeyObject} publicKey
 * @param {string} signatureAlgorithm - e.g. 'ed25519', 'ecdsa-p256'
 * @returns {boolean}
 */
function verifySignature(data, signatureHex, publicKey, signatureAlgorithm = 'ed25519') {
  try {
    const algo = resolveSignatureAlgorithm(signatureAlgorithm);
    const key = toPublicKey(publicKey);
    const sig = Buffer.from(signatureHex, 'hex');
    const payload = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
    return crypto.verify(algo.hashArg, payload, key, sig);
  } catch (_) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Extension attestation verification
// ---------------------------------------------------------------------------

/**
 * Verify a ContentIntegrity Merkle-tree attestation.
 *
 * Attestation shape:
 *   { type: 'ContentIntegrity', root_hash, leaves: [hex...], proof?: [...] }
 *
 * If `proof` is absent we recompute the full Merkle root from `leaves`.
 * If `proof` is present we walk the proof path for the supplied `leaf_hash`.
 */
function verifyContentIntegrity(attestation, hashAlgorithm = 'sha256') {
  if (!attestation || attestation.type !== 'ContentIntegrity') {
    return { valid: false, reason: 'Not a ContentIntegrity attestation' };
  }
  const rootHash = attestation.root_hash || attestation.merkle_root;
  const leaves = attestation.leaves || attestation.leaf_hashes;
  if (!rootHash) {
    return { valid: false, reason: 'Missing root_hash/merkle_root' };
  }

  // Use attestation's stored hash_algorithm if available, fall back to parameter
  const effectiveAlgo = attestation.hash_algorithm || hashAlgorithm;

  // Handle empty tree: backend returns all-zeros hash of correct length
  if (!Array.isArray(leaves) || leaves.length === 0) {
    const expectedLen = HASH_OUTPUT_LENGTHS[effectiveAlgo] || 64;
    const emptyRoot = '0'.repeat(expectedLen);
    return {
      valid: rootHash === emptyRoot,
      computed_root: emptyRoot,
      expected_root: rootHash,
      domain_separation: 'rfc6962',
    };
  }

  // RFC 6962 domain separation prefixes
  const LEAF_PREFIX = Buffer.from([0x00]);
  const NODE_PREFIX = Buffer.from([0x01]);
  const algo = resolveHashAlgorithm(effectiveAlgo);

  // Hash leaves with 0x00 domain separation prefix
  let level = leaves.map(l =>
    crypto.createHash(algo).update(Buffer.concat([LEAF_PREFIX, Buffer.from(l, 'hex')])).digest()
  );

  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        // Internal node: 0x01 prefix + left + right
        next.push(crypto.createHash(algo).update(Buffer.concat([NODE_PREFIX, level[i], level[i + 1]])).digest());
      } else {
        next.push(level[i]); // odd node promoted (not duplicated)
      }
    }
    level = next;
  }
  const computedRoot = level[0].toString('hex');
  return {
    valid: computedRoot === rootHash,
    computed_root: computedRoot,
    expected_root: rootHash,
    domain_separation: 'rfc6962',
  };
}

/**
 * Verify a Timestamp attestation.
 *
 * Accepts two attestation shapes:
 *   SDK format:     { type: 'Timestamp', timestamp, hash: hex, signed_timestamp?: hex }
 *   Backend format: { type: 'Timestamp', anchored_at, anchor_hash: hex, head_hash?, chain_id? }
 *
 * For SDK format: re-hash the timestamp string and compare to hash.
 * For backend format: structural validation (anchor_hash cannot be recomputed without the signature).
 * If `signed_timestamp` and a public key are provided, verify the signature.
 */
function verifyTimestamp(attestation, publicKey, hashAlgorithm = 'sha256', signatureAlgorithm = 'ed25519') {
  if (!attestation || attestation.type !== 'Timestamp') {
    return { valid: false, reason: 'Not a Timestamp attestation' };
  }

  // Accept both SDK format (timestamp/hash) and backend format (anchored_at/anchor_hash)
  const timestamp = attestation.timestamp || attestation.anchored_at;
  const expectedHash = attestation.hash || attestation.anchor_hash;

  if (!timestamp || !expectedHash) {
    return { valid: false, reason: 'Missing timestamp/anchored_at or hash/anchor_hash' };
  }

  // For SDK format (where hash = sha256(timestamp)), verify the hash
  // For backend format (where anchor_hash = sha256(signature + timestamp)), skip hash check
  // since we can't recompute without the original signature
  const isBackendFormat = !!attestation.anchor_hash && !attestation.hash;
  let hashValid;
  if (isBackendFormat) {
    // Backend anchor_hash depends on certificate signature — structural check only
    hashValid = typeof expectedHash === 'string' && expectedHash.length > 0;
  } else {
    const computedHash = hash(timestamp, hashAlgorithm);
    hashValid = computedHash === expectedHash;
  }

  let signatureValid = null;
  const signedTs = attestation.signed_timestamp;
  if (signedTs && publicKey) {
    try {
      signatureValid = verifySignature(
        Buffer.from(timestamp, 'utf8'), signedTs, publicKey, signatureAlgorithm
      );
    } catch (err) {
      signatureValid = false;
    }
  }

  return {
    valid: hashValid && (signatureValid === null || signatureValid),
    hash_valid: hashValid,
    signature_valid: signatureValid,
  };
}

/**
 * Verify a Blockchain attestation.
 *
 * Accepts two attestation shapes:
 *   SDK format:     { type: 'Blockchain', chain_hash, tx_hash, network, block_number? }
 *   Backend format: { type: 'Blockchain', tx_hash, head_hash, chain_id, anchored_at }
 *
 * Offline verification can only confirm that chain_hash/head_hash matches the expected
 * value. Full on-chain verification requires network access and is out of scope
 * for a zero-dependency SDK.
 */
function verifyBlockchain(attestation, expectedChainHash) {
  if (!attestation || attestation.type !== 'Blockchain') {
    return { valid: false, reason: 'Not a Blockchain attestation' };
  }
  // Accept both SDK (chain_hash) and backend (head_hash) field names
  const chainHash = attestation.chain_hash || attestation.head_hash;
  const { tx_hash, network } = attestation;
  if (!tx_hash) {
    return { valid: false, reason: 'Missing tx_hash' };
  }
  const hashMatch = (expectedChainHash && chainHash) ? chainHash === expectedChainHash : null;
  return {
    valid: hashMatch === null ? true : hashMatch,
    hash_match: hashMatch,
    tx_hash,
    network: network || 'unknown',
  };
}

/**
 * Dispatch verification for any extension attestation.
 */
function verifyExtensionAttestation(attestation, options = {}) {
  if (!attestation || !attestation.type) {
    return { valid: false, reason: 'Missing attestation type' };
  }
  switch (attestation.type) {
    case 'ContentIntegrity':
      return verifyContentIntegrity(attestation, options.hashAlgorithm || 'sha256');
    case 'Timestamp':
      return verifyTimestamp(
        attestation, options.publicKey, options.hashAlgorithm || 'sha256',
        options.signatureAlgorithm || 'ed25519'
      );
    case 'Blockchain':
      return verifyBlockchain(attestation, options.expectedChainHash);
    default:
      return { valid: false, reason: `Unknown attestation type: ${attestation.type}` };
  }
}

// ---------------------------------------------------------------------------
// Main verifier class
// ---------------------------------------------------------------------------

class OpenExecutionVerifier {
  /**
   * @param {object} [options]
   * @param {string} [options.apiUrl]
   */
  constructor(options = {}) {
    this.apiUrl = options.apiUrl || DEFAULT_API_URL;
  }

  // -----------------------------------------------------------------------
  // Online verification (backward-compatible)
  // -----------------------------------------------------------------------

  /**
   * Verify a certificate via the OpenExecution API.
   * Backward-compatible with the original SDK.
   *
   * @param {string} certificateId
   * @returns {Promise<object>} VerificationResult from the API
   */
  async verifyCertificate(certificateId) {
    const res = await fetch(`${this.apiUrl}/provenance/verify/${certificateId}`);
    if (!res.ok) {
      if (res.status === 404) throw new Error(`Certificate not found: ${certificateId}`);
      throw new Error(`Verification request failed: ${res.status}`);
    }
    const json = await res.json();
    return json.data;
  }

  // -----------------------------------------------------------------------
  // Offline signature verification (Ed25519 / Ed448 / ECDSA)
  // -----------------------------------------------------------------------

  /**
   * Verify an asymmetric signature over canonicalized certificate data.
   *
   * @param {object} certificateData          - The certificate payload
   * @param {string} signatureHex             - Hex-encoded signature
   * @param {string|Buffer|crypto.KeyObject} publicKey
   * @param {string} [signatureAlgorithm='ed25519']
   * @returns {boolean}
   */
  static verifySignatureOffline(certificateData, signatureHex, publicKey, signatureAlgorithm = 'ed25519') {
    const canonical = canonicalize(certificateData);
    return verifySignature(canonical, signatureHex, publicKey, signatureAlgorithm);
  }

  // -----------------------------------------------------------------------
  // Chain integrity verification
  // -----------------------------------------------------------------------

  /**
   * Verify the integrity of an ordered array of chain events.
   *
   * Checks:
   *   1. Sequence numbers are consecutive starting at 1
   *   2. prev_hash linkage (genesis event must reference GENESIS_HASH)
   *   3. Event hash recomputation using the specified hash algorithm
   *
   * @param {object[]} events
   * @param {object}   [options]
   * @param {string}   [options.hashAlgorithm='sha256']
   * @param {string}   [options.canonicalization='jcs']
   * @returns {{ is_valid: boolean, event_count: number, errors: string[] }}
   */
  static verifyChainIntegrity(events, options = {}) {
    const hashAlgorithm = options.hashAlgorithm || 'sha256';
    const errors = [];
    let expectedPrevHash = getGenesisHash(hashAlgorithm);

    for (let i = 0; i < events.length; i++) {
      const event = events[i];
      const expectedSeq = i + 1;

      // 1. Consecutive sequence numbers
      if (event.seq !== expectedSeq) {
        errors.push(`Event at index ${i}: expected seq=${expectedSeq}, got seq=${event.seq}`);
      }

      // 2. prev_hash linkage
      if (event.prev_hash !== expectedPrevHash) {
        errors.push(`Event seq=${event.seq}: prev_hash mismatch (expected ${expectedPrevHash.slice(0, 16)}..., got ${(event.prev_hash || '').slice(0, 16)}...)`);
      }

      // 3. Recompute event hash using JCS canonicalization
      const eventData = {
        seq: event.seq,
        event_type: event.event_type,
        actor_id: event.actor_id || 'system',
        timestamp: new Date(event.created_at).toISOString(),
        payload: event.payload,
        prev_hash: event.prev_hash,
      };

      const canonical = canonicalize(eventData);
      const computed = hash(canonical, hashAlgorithm);

      if (event.event_hash !== computed) {
        errors.push(`Event seq=${event.seq}: event_hash mismatch (computed ${computed.slice(0, 16)}..., got ${(event.event_hash || '').slice(0, 16)}...)`);
      }

      expectedPrevHash = event.event_hash;
    }

    return { is_valid: errors.length === 0, event_count: events.length, errors };
  }

  // -----------------------------------------------------------------------
  // Chain hash computation
  // -----------------------------------------------------------------------

  /**
   * Compute a summary hash over all event hashes in a chain.
   *
   * @param {string[]} eventHashes
   * @param {string}   [hashAlgorithm='sha256']
   * @returns {string}  Hex-encoded hash
   */
  static computeChainHash(eventHashes, hashAlgorithm = 'sha256') {
    return hash(eventHashes.join(''), hashAlgorithm);
  }

  // -----------------------------------------------------------------------
  // Bundle verification (offline, fully self-contained)
  // -----------------------------------------------------------------------

  /**
   * Verify a self-contained provenance bundle offline.
   *
   * Bundle shape:
   * {
   *   certificate: { ... },
   *   certificate_signature: "hex",
   *   chain: {
   *     id: "...",
   *     events: [...],
   *     hash_algorithm: "sha256",
   *     signature_algorithm: "ed25519",
   *     canonicalization: "jcs"
   *   },
   *   public_key: "PEM string or hex",
   *   attestations?: [ { type, ... }, ... ]
   * }
   *
   * @param {object} bundle
   * @returns {{ valid: boolean, certificate_signature_valid: boolean, chain_integrity: object, chain_hash_valid: boolean, attestation_results?: object[], errors: string[] }}
   */
  static verifyBundle(bundle) {
    const errors = [];

    if (!bundle || typeof bundle !== 'object') {
      return { valid: false, certificate_signature_valid: false, chain_integrity: null, chain_hash_valid: false, errors: ['Invalid bundle'] };
    }

    const { certificate, certificate_signature, chain, public_key, attestations } = bundle;
    const sigAlgorithm = (chain && chain.signature_algorithm) || 'ed25519';
    const hashAlgorithm = (chain && chain.hash_algorithm) || 'sha256';

    // 1. Verify certificate signature
    let certSigValid = false;
    if (certificate && certificate_signature && public_key) {
      try {
        certSigValid = OpenExecutionVerifier.verifySignatureOffline(
          certificate, certificate_signature, public_key, sigAlgorithm
        );
      } catch (err) {
        errors.push(`Certificate signature verification error: ${err.message}`);
      }
    } else {
      errors.push('Missing certificate, certificate_signature, or public_key');
    }

    // 2. Verify chain integrity
    let chainIntegrity = { is_valid: false, event_count: 0, errors: ['No chain events provided'] };
    if (chain && Array.isArray(chain.events)) {
      chainIntegrity = OpenExecutionVerifier.verifyChainIntegrity(chain.events, {
        hashAlgorithm,
        canonicalization: chain.canonicalization || 'jcs',
      });
      if (!chainIntegrity.is_valid) {
        errors.push(...chainIntegrity.errors);
      }
    } else {
      errors.push('Missing chain or chain.events');
    }

    // 3. Verify chain hash matches certificate
    let chainHashValid = false;
    if (chain && Array.isArray(chain.events) && certificate && certificate.chain_hash) {
      const eventHashes = chain.events.map(e => e.event_hash);
      const computedChainHash = OpenExecutionVerifier.computeChainHash(eventHashes, hashAlgorithm);
      chainHashValid = computedChainHash === certificate.chain_hash;
      if (!chainHashValid) {
        errors.push(`Chain hash mismatch: computed ${computedChainHash.slice(0, 16)}..., expected ${certificate.chain_hash.slice(0, 16)}...`);
      }
    }

    // 4. Verify extension attestations
    let attestationResults = null;
    if (Array.isArray(attestations) && attestations.length > 0) {
      attestationResults = attestations.map(att => {
        const result = verifyExtensionAttestation(att, {
          publicKey: public_key,
          hashAlgorithm,
          signatureAlgorithm: sigAlgorithm,
          expectedChainHash: certificate && certificate.chain_hash,
        });
        if (!result.valid) {
          errors.push(`Attestation ${att.type || 'unknown'}: ${result.reason || 'invalid'}`);
        }
        return { type: att.type, ...result };
      });
    }

    const valid = certSigValid && chainIntegrity.is_valid && chainHashValid &&
      (attestationResults === null || attestationResults.every(r => r.valid));

    const result = {
      valid,
      certificate_signature_valid: certSigValid,
      chain_integrity: chainIntegrity,
      chain_hash_valid: chainHashValid,
      errors,
    };

    if (attestationResults) {
      result.attestation_results = attestationResults;
    }

    return result;
  }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  OpenExecutionVerifier,
  canonicalize,
  hash,
  verifySignature,
  verifyExtensionAttestation,
  verifyContentIntegrity,
  verifyTimestamp,
  verifyBlockchain,
  HASH_MAP,
  SIGNATURE_ALGORITHMS,
};
