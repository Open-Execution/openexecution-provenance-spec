# OpenExecution Verification Protocol

**Version:** 1.0.0
**Status:** Active
**Last Updated:** 2026-02-14

## 1. Overview

The OpenExecution Verification Protocol defines how any third party -- auditors, courts, regulators, counterparties -- can independently verify the authenticity and integrity of a Provenance Certificate without any cooperation from the platform.

This is the protocol that makes OpenExecution fundamentally different from observability tools. LangSmith, LangFuse, and Helicone produce internal records that the operator controls. OpenExecution produces Ed25519-signed certificates verifiable by anyone with the published public key. Platform logs lie. Cryptography doesn't.

Verification can be performed using the public verification API endpoint or offline using the provided SDKs.

The protocol validates three properties:

1. **Signature validity (L3 -- Independent Accountability)** -- the Ed25519 signature confirms the certificate data has not been tampered with since issuance, verifiable by anyone with the public key.
2. **Chain hash validity (L2 -- Tamper-Proof Causality)** -- the chain hash in the certificate matches the recomputed hash from the chain's events. One changed byte breaks the entire chain.
3. **Chain integrity (L1 -- Behavior Recording)** -- the hash chain of events is unbroken and each event's hash is correct, proving the complete behavioral record is intact.

## 2. Verification Endpoint

```
GET /api/v1/provenance/verify/:certificateId
```

**Parameters:**

| Parameter | Location | Type | Description |
|-----------|----------|------|-------------|
| `certificateId` | path | UUID | The provenance certificate ID to verify. |

**Response:** See Section 6 for the complete response format.

## 3. Verification Steps

### Step 1: Fetch the Certificate

Retrieve the provenance certificate by its ID from the verification endpoint:

```
GET /api/v1/provenance/verify/{certificateId}
```

If the certificate does not exist, the endpoint returns a `404 Not Found` response. If the certificate has been revoked, the response includes the certificate with `status: "revoked"` and `valid: false`.

### Step 2: Verify the Certificate Signature

Verify the Ed25519 signature of the `certificate_data` field using the platform's published public key:

1. Extract the `certificate_data` JSON object from the certificate.
2. Serialize it as canonical JSON (all keys sorted alphabetically at every nesting level).
3. Fetch the platform's Ed25519 public key from `GET /api/v1/provenance/public-key`.
4. Verify the signature: `Ed25519.verify(public_key, canonical_json, certificate_signature)`.

```
canonical_json = JSON.stringify(certificate_data, Object.keys(certificate_data).sort())
signature_valid = Ed25519.verify(public_key, canonical_json, certificate_signature)
```

**Note:** Unlike symmetric signing schemes (HMAC), Ed25519 verification requires only the public key. Any third party can perform this step independently -- no platform secrets or cooperation required. This is what makes OpenExecution certificates court-ready evidence.

### Step 3: Fetch Chain Events

Retrieve all chain events for the execution chain referenced by the certificate's `chain_id`. Events must be ordered by `seq` in ascending order.

### Step 4: Verify Hash Chain Integrity

Iterate through the chain events in sequence order and verify:

1. **Genesis check:** The first event (seq=0) must have `prev_hash` equal to the genesis hash (`'0'.repeat(64)`).
2. **Linkage check:** For each subsequent event, `prev_hash` must equal the preceding event's `event_hash`.
3. **Hash check:** For each event, recompute the event hash and compare with the stored `event_hash`.

Event hash recomputation:

```
event_data = JSON.stringify({
  seq: event.seq,
  event_type: event.event_type,
  agent_id: event.agent_id || 'system',
  timestamp: event.created_at (ISO-8601),
  payload: event.payload,
  prev_hash: event.prev_hash
})

computed_hash = SHA-256(event_data)
```

If any event fails the linkage or hash check, the chain integrity is invalid.

### Step 5: Compute Chain Hash

Compute the chain hash by concatenating all event hashes in sequence order and hashing the result:

```
chain_hash = SHA-256(event_hash[0] + event_hash[1] + ... + event_hash[N])
```

### Step 6: Compare Chain Hash

Compare the computed chain hash from Step 5 with the `chain_hash` stored in both the certificate and the execution chain record. All three values must match.

### Step 7: Return Verification Result

Assemble the verification result object (see Section 6).

## 4. Verification Decision Matrix

| Signature Valid | Chain Hash Valid | Chain Integrity | Certificate Status | Result |
|:-:|:-:|:-:|:---:|:---:|
| Yes | Yes | Yes | active | **VALID** |
| Yes | Yes | Yes | revoked | **INVALID** (revoked) |
| Yes | Yes | Yes | superseded | **INVALID** (superseded) |
| No | -- | -- | any | **INVALID** (signature tampered) |
| -- | No | -- | any | **INVALID** (chain hash mismatch) |
| -- | -- | No | any | **INVALID** (chain tampered) |

A certificate is considered **VALID** only when all three checks pass and the certificate status is `active`.

## 5. Error Conditions

| Condition | HTTP Status | Error |
|-----------|:-----------:|-------|
| Certificate not found | 404 | `Certificate not found: {certificateId}` |
| Certificate revoked | 200 | Returns result with `valid: false`, `certificate.status: "revoked"` |
| Certificate superseded | 200 | Returns result with `valid: false`, `certificate.status: "superseded"` |
| Chain events missing | 200 | Returns result with `chain_hash_valid: false` |
| Internal error | 500 | `Verification failed: internal error` |

## 6. Response Format

The verification endpoint returns the following JSON structure:

```json
{
  "data": {
    "valid": true,
    "signature_valid": true,
    "chain_hash_valid": true,
    "certificate": {
      "id": "uuid",
      "chain_id": "uuid",
      "artifact_type": "answer",
      "artifact_ref": "uuid",
      "status": "active"
    },
    "chain": {
      "id": "uuid",
      "chain_type": "question_resolution",
      "status": "certified"
    },
    "integrity": {
      "chain_id": "uuid",
      "event_count": 5,
      "is_valid": true,
      "errors": []
    }
  }
}
```

### 6.1 Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `valid` | boolean | Overall verification result. `true` only if all checks pass and certificate is active. |
| `signature_valid` | boolean | Whether the Ed25519 signature matches the certificate data (verified using the public key). |
| `chain_hash_valid` | boolean | Whether the recomputed chain hash matches the stored chain hash. |
| `certificate` | object | Summary of the certificate being verified. |
| `certificate.id` | string | Certificate UUID. |
| `certificate.chain_id` | string | The execution chain this certificate attests to. |
| `certificate.artifact_type` | string | The type of certified artifact. |
| `certificate.artifact_ref` | string | Reference identifier for the artifact. |
| `certificate.status` | string | Current certificate status (`active`, `revoked`, `superseded`). |
| `chain` | object | Summary of the execution chain. |
| `chain.id` | string | Chain UUID. |
| `chain.chain_type` | string | The type of execution chain. |
| `chain.status` | string | Current chain status. |
| `integrity` | object | Chain integrity check results. |
| `integrity.chain_id` | string | The chain that was checked. |
| `integrity.event_count` | integer | Number of events verified. |
| `integrity.is_valid` | boolean | Whether the hash chain is intact. |
| `integrity.errors` | string[] | Array of error descriptions (empty if valid). |

## 7. Offline Verification

Third-party implementations can perform full cryptographic verification offline using the provided SDKs and the platform's published Ed25519 public key:

- **Chain integrity verification** can be performed entirely offline given the chain events data.
- **Signature verification** requires only the Ed25519 public key (available at the well-known API endpoint and cacheable). Unlike HMAC-based schemes, no shared secret is needed -- anyone can verify.
- **Certificate status** must be checked against the live API to confirm the certificate has not been revoked.

This independent verifiability is the architectural foundation of OpenExecution's legal admissibility. Ed25519 satisfies eIDAS "advanced electronic signature" requirements and China's Electronic Signature Law (Article 13).

See the [JavaScript SDK](../sdk/js/) and [Python SDK](../sdk/python/) for implementation details.

## 8. References

- [Provenance Certificate Specification](./provenance-certificate.md)
- [Hash Chain Algorithm](./hash-chain.md)
- [Execution Chain Specification](./execution-chain.md)
- [Chain Events Specification](./chain-events.md)
