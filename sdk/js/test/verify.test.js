'use strict';

const crypto = require('crypto');
const {
  OpenExecutionVerifier,
  canonicalize,
  hash,
  verifySignature,
  verifyContentIntegrity,
  verifyTimestamp,
  verifyBlockchain,
  HASH_MAP,
  SIGNATURE_ALGORITHMS,
} = require('../src/verify.js');

const assert = require('assert');

// ── Canonicalize (JCS / RFC 8785) ──

assert.strictEqual(canonicalize(null), 'null');
assert.strictEqual(canonicalize(42), '42');
assert.strictEqual(canonicalize('hello'), '"hello"');
assert.strictEqual(canonicalize([1, 2]), '[1,2]');
assert.strictEqual(
  canonicalize({ b: 2, a: 1 }),
  '{"a":1,"b":2}',
  'Keys must be sorted'
);
assert.strictEqual(
  canonicalize({ b: undefined, a: 1 }),
  '{"a":1}',
  'Undefined values omitted per RFC 8785'
);

// ── Hash ──

const sha256Hello = hash('hello', 'sha256');
assert.strictEqual(sha256Hello.length, 64);
assert.strictEqual(
  sha256Hello,
  crypto.createHash('sha256').update('hello').digest('hex')
);

for (const algo of Object.keys(HASH_MAP)) {
  const h = hash('test', algo);
  assert.ok(h.length > 0, `hash(${algo}) should produce output`);
}

assert.throws(() => hash('x', 'md5'), /Unsupported hash algorithm/);

// ── Signature ──

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const data = Buffer.from('test-payload');
const sig = crypto.sign(null, data, privateKey).toString('hex');

assert.strictEqual(verifySignature(data, sig, publicKey, 'ed25519'), true);
assert.strictEqual(verifySignature(Buffer.from('wrong'), sig, publicKey, 'ed25519'), false);
assert.strictEqual(verifySignature(data, 'bad', publicKey, 'ed25519'), false);

// ── Chain Integrity ──

function buildChain(n, hashAlgorithm = 'sha256') {
  const genesisLen = hashAlgorithm === 'sha256' ? 64 : 128;
  let prevHash = '0'.repeat(genesisLen);
  const events = [];
  for (let i = 1; i <= n; i++) {
    const eventData = {
      seq: i,
      event_type: 'test',
      actor_id: 'system',
      timestamp: new Date(1700000000000 + i * 1000).toISOString(),
      payload: { value: i },
      prev_hash: prevHash,
    };
    const eventHash = hash(canonicalize(eventData), hashAlgorithm);
    events.push({
      seq: i,
      event_type: 'test',
      actor_id: 'system',
      created_at: eventData.timestamp,
      payload: { value: i },
      prev_hash: prevHash,
      event_hash: eventHash,
    });
    prevHash = eventHash;
  }
  return events;
}

const chain3 = buildChain(3);
const result3 = OpenExecutionVerifier.verifyChainIntegrity(chain3);
assert.strictEqual(result3.is_valid, true);
assert.strictEqual(result3.event_count, 3);
assert.strictEqual(result3.errors.length, 0);

// Tampered chain
const tampered = JSON.parse(JSON.stringify(chain3));
tampered[1].event_hash = 'deadbeef'.repeat(8);
const resultTampered = OpenExecutionVerifier.verifyChainIntegrity(tampered);
assert.strictEqual(resultTampered.is_valid, false);
assert.ok(resultTampered.errors.length > 0);

// Empty chain
const resultEmpty = OpenExecutionVerifier.verifyChainIntegrity([]);
assert.strictEqual(resultEmpty.is_valid, true);
assert.strictEqual(resultEmpty.event_count, 0);

// ── Chain Hash ──

const hashes = chain3.map(e => e.event_hash);
const chainHash = OpenExecutionVerifier.computeChainHash(hashes);
assert.strictEqual(chainHash.length, 64);
assert.strictEqual(chainHash, hash(hashes.join(''), 'sha256'));

// ── Content Integrity (Merkle) ──

const leaf1 = hash('data1', 'sha256');
const leaf2 = hash('data2', 'sha256');
const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);
const h1 = crypto.createHash('sha256').update(Buffer.concat([LEAF_PREFIX, Buffer.from(leaf1, 'hex')])).digest();
const h2 = crypto.createHash('sha256').update(Buffer.concat([LEAF_PREFIX, Buffer.from(leaf2, 'hex')])).digest();
const root = crypto.createHash('sha256').update(Buffer.concat([NODE_PREFIX, h1, h2])).digest('hex');

const ciResult = verifyContentIntegrity({
  type: 'ContentIntegrity',
  root_hash: root,
  leaves: [leaf1, leaf2],
});
assert.strictEqual(ciResult.valid, true);

const ciBadRoot = verifyContentIntegrity({
  type: 'ContentIntegrity',
  root_hash: 'wrong',
  leaves: [leaf1, leaf2],
});
assert.strictEqual(ciBadRoot.valid, false);

// Empty leaves
const ciEmpty = verifyContentIntegrity({
  type: 'ContentIntegrity',
  root_hash: '0'.repeat(64),
  leaves: [],
});
assert.strictEqual(ciEmpty.valid, true);

// ── Timestamp ──

const ts = new Date().toISOString();
const tsHash = hash(ts, 'sha256');
const tsResult = verifyTimestamp({ type: 'Timestamp', timestamp: ts, hash: tsHash });
assert.strictEqual(tsResult.valid, true);
assert.strictEqual(tsResult.hash_valid, true);

const tsBad = verifyTimestamp({ type: 'Timestamp', timestamp: ts, hash: 'wrong' });
assert.strictEqual(tsBad.valid, false);

// ── Blockchain ──

const bcResult = verifyBlockchain(
  { type: 'Blockchain', chain_hash: 'abc', tx_hash: '0x123', network: 'ethereum' },
  'abc'
);
assert.strictEqual(bcResult.valid, true);

const bcMismatch = verifyBlockchain(
  { type: 'Blockchain', chain_hash: 'abc', tx_hash: '0x123' },
  'xyz'
);
assert.strictEqual(bcMismatch.valid, false);

// ── Bundle ──

const chainEvents = buildChain(2);
const eventHashes = chainEvents.map(e => e.event_hash);
const bundleChainHash = OpenExecutionVerifier.computeChainHash(eventHashes);
const cert = { chain_hash: bundleChainHash, scope: 'test' };
const certCanonical = canonicalize(cert);
const certSig = crypto.sign(null, Buffer.from(certCanonical), privateKey).toString('hex');
const pemKey = publicKey.export({ type: 'spki', format: 'pem' });

const bundle = {
  certificate: cert,
  certificate_signature: certSig,
  chain: { events: chainEvents, hash_algorithm: 'sha256', signature_algorithm: 'ed25519', canonicalization: 'jcs' },
  public_key: pemKey,
};
const bundleResult = OpenExecutionVerifier.verifyBundle(bundle);
assert.strictEqual(bundleResult.valid, true);
assert.strictEqual(bundleResult.certificate_signature_valid, true);
assert.strictEqual(bundleResult.chain_integrity.is_valid, true);
assert.strictEqual(bundleResult.chain_hash_valid, true);

console.log('All 25 tests passed.');
