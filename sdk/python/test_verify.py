"""Unit tests for the OpenExecution Python Verification SDK."""

import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from openexecution_verify import (
    OpenExecutionVerifier,
    canonicalize,
    compute_hash,
    verify_signature,
    verify_content_integrity,
    verify_timestamp,
    verify_blockchain,
    SUPPORTED_HASH_ALGORITHMS,
    SUPPORTED_SIG_ALGORITHMS,
)

# ── Canonicalize (JCS / RFC 8785) ──

assert canonicalize(None) == "null"
assert canonicalize(42) == "42"
assert canonicalize("hello") == '"hello"'
assert canonicalize([1, 2]) == "[1,2]"
assert canonicalize({"b": 2, "a": 1}) == '{"a":1,"b":2}', "Keys must be sorted"
assert canonicalize(True) == "true"
assert canonicalize(False) == "false"

# ── Hash ──

sha256_hello = compute_hash(b"hello", "sha256")
assert len(sha256_hello) == 64
assert sha256_hello == hashlib.sha256(b"hello").hexdigest()

for algo in SUPPORTED_HASH_ALGORITHMS:
    h = compute_hash(b"test", algo)
    assert len(h) > 0, f"compute_hash({algo}) should produce output"

try:
    compute_hash(b"x", "md5")
    assert False, "Should have raised ValueError"
except ValueError as e:
    assert "Unsupported hash algorithm" in str(e)

# ── Signature ──

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()
pem_pub = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

data = b"test-payload"
sig = private_key.sign(data).hex()

assert verify_signature(data, sig, public_key, "ed25519") is True
assert verify_signature(b"wrong", sig, public_key, "ed25519") is False
assert verify_signature(data, "00" * 64, public_key, "ed25519") is False

# PEM string key also works
assert verify_signature(data, sig, pem_pub, "ed25519") is True

# ── Chain Integrity ──

def build_chain(n, hash_algorithm="sha256"):
    genesis_len = 64 if hash_algorithm == "sha256" else 128
    prev_hash = "0" * genesis_len
    events = []
    for i in range(1, n + 1):
        ts = datetime(2023, 11, 15, 0, 0, i, tzinfo=timezone.utc)
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
        event_data = {
            "seq": i,
            "event_type": "test",
            "actor_id": "system",
            "timestamp": ts_str,
            "payload": {"value": i},
            "prev_hash": prev_hash,
        }
        event_hash = compute_hash(canonicalize(event_data).encode("utf-8"), hash_algorithm)
        events.append({
            "seq": i,
            "event_type": "test",
            "actor_id": "system",
            "created_at": ts_str,
            "payload": {"value": i},
            "prev_hash": prev_hash,
            "event_hash": event_hash,
        })
        prev_hash = event_hash
    return events

chain3 = build_chain(3)
result3 = OpenExecutionVerifier.verify_chain_integrity(chain3)
assert result3["is_valid"] is True
assert result3["event_count"] == 3
assert len(result3["errors"]) == 0

# Tampered chain
import copy
tampered = copy.deepcopy(chain3)
tampered[1]["event_hash"] = "deadbeef" * 8
result_tampered = OpenExecutionVerifier.verify_chain_integrity(tampered)
assert result_tampered["is_valid"] is False
assert len(result_tampered["errors"]) > 0

# Empty chain
result_empty = OpenExecutionVerifier.verify_chain_integrity([])
assert result_empty["is_valid"] is True
assert result_empty["event_count"] == 0

# ── Chain Hash ──

hashes = [e["event_hash"] for e in chain3]
chain_hash = OpenExecutionVerifier.compute_chain_hash(hashes)
assert len(chain_hash) == 64
assert chain_hash == compute_hash("".join(hashes).encode("utf-8"), "sha256")

# ── Content Integrity (Merkle) ──

leaf1 = compute_hash(b"data1", "sha256")
leaf2 = compute_hash(b"data2", "sha256")
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
h1 = hashlib.sha256(LEAF_PREFIX + bytes.fromhex(leaf1)).digest()
h2 = hashlib.sha256(LEAF_PREFIX + bytes.fromhex(leaf2)).digest()
root = hashlib.sha256(NODE_PREFIX + h1 + h2).hexdigest()

ci_result = verify_content_integrity({
    "type": "ContentIntegrity",
    "root_hash": root,
    "leaves": [leaf1, leaf2],
})
assert ci_result["valid"] is True

ci_bad_root = verify_content_integrity({
    "type": "ContentIntegrity",
    "root_hash": "wrong",
    "leaves": [leaf1, leaf2],
})
assert ci_bad_root["valid"] is False

# Empty leaves
ci_empty = verify_content_integrity({
    "type": "ContentIntegrity",
    "root_hash": "0" * 64,
    "leaves": [],
})
assert ci_empty["valid"] is True

# ── Timestamp ──

ts = datetime.now(timezone.utc).isoformat()
ts_hash = compute_hash(ts.encode("utf-8"), "sha256")
ts_result = verify_timestamp({"type": "Timestamp", "timestamp": ts, "hash": ts_hash})
assert ts_result["valid"] is True
assert ts_result["hash_valid"] is True

ts_bad = verify_timestamp({"type": "Timestamp", "timestamp": ts, "hash": "wrong"})
assert ts_bad["valid"] is False

# ── Blockchain ──

bc_result = verify_blockchain(
    {"type": "Blockchain", "chain_hash": "abc", "tx_hash": "0x123", "network": "ethereum"},
    "abc",
)
assert bc_result["valid"] is True

bc_mismatch = verify_blockchain(
    {"type": "Blockchain", "chain_hash": "abc", "tx_hash": "0x123"},
    "xyz",
)
assert bc_mismatch["valid"] is False

# ── Bundle ──

chain_events = build_chain(2)
event_hashes = [e["event_hash"] for e in chain_events]
bundle_chain_hash = OpenExecutionVerifier.compute_chain_hash(event_hashes)
cert = {"chain_hash": bundle_chain_hash, "scope": "test"}
cert_canonical = canonicalize(cert).encode("utf-8")
cert_sig = private_key.sign(cert_canonical).hex()

verifier = OpenExecutionVerifier()
bundle = {
    "certificate": cert,
    "certificate_signature": cert_sig,
    "chain": {
        "events": chain_events,
        "hash_algorithm": "sha256",
        "signature_algorithm": "ed25519",
        "canonicalization": "jcs",
    },
    "public_key": pem_pub,
}
bundle_result = verifier.verify_bundle(bundle)
assert bundle_result["valid"] is True
assert bundle_result["certificate_signature_valid"] is True
assert bundle_result["chain_integrity"]["is_valid"] is True
assert bundle_result["chain_hash_valid"] is True

print("All 25 tests passed.")
