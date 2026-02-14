# OpenExecution Hash Chain Algorithm

**Version:** 1.0.0
**Status:** Active
**Last Updated:** 2026-02-14

## 1. Overview

The hash chain algorithm is the cryptographic backbone of the OpenExecution behavioral ledger -- **L2: Tamper-Proof Causality** in the three-layer accountability stack. It ensures that every event in an execution chain is linked to its predecessor via a SHA-256 hash, forming a tamper-evident sequence. One changed byte breaks the entire chain, making unauthorized alterations immediately detectable.

This is what separates cryptographic provenance from platform logging. Observability tools store plain database records that the operator can edit at will. A SHA-256 hash chain is append-only by construction: altering any event cascades hash failures through every subsequent event and invalidates the chain hash embedded in the Ed25519-signed Provenance Certificate.

## 2. Genesis Hash

The genesis hash is a fixed sentinel value used as the `prev_hash` for the first event (seq=0) in every chain:

```
GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000'
```

This is a string of 64 zero characters (`'0'.repeat(64)`). It serves as the anchor point for the hash chain.

## 3. Event Hash Computation

Each event's hash is computed as the SHA-256 digest of a JSON-serialized object containing the event's core fields:

### 3.1 Input Object

```javascript
{
  seq: <integer>,           // Event sequence number (0-indexed)
  event_type: <string>,     // Event type identifier
  agent_id: <string>,       // Agent UUID or 'system' if agent_id is null
  timestamp: <string>,      // ISO-8601 timestamp (e.g., '2026-02-14T12:00:00.000Z')
  payload: <object>,        // Event payload (JSONB)
  prev_hash: <string>       // Hash of the previous event, or GENESIS_HASH for seq=0
}
```

### 3.2 Computation

```
event_hash = SHA-256(JSON.stringify(input_object))
```

The `JSON.stringify` function uses the default serialization (keys in the order listed above). The resulting hash is a lowercase hexadecimal string of 64 characters.

### 3.3 Agent ID Normalization

If the event's `agent_id` is `null` (system event), it is normalized to the string `'system'` before hashing:

```javascript
agent_id: event.agent_id || 'system'
```

### 3.4 Timestamp Format

The `timestamp` field must be an ISO-8601 string. When reading from the database, the `created_at` timestamp is converted to ISO-8601 format:

```javascript
timestamp: new Date(event.created_at).toISOString()
```

This ensures consistent serialization across different platforms and time zones.

## 4. Chain Hash Computation

The chain hash is a single SHA-256 digest that summarizes the entire chain's event history:

### 4.1 Algorithm

1. Collect all event hashes from the chain, ordered by `seq` in ascending order.
2. Concatenate the event hash strings (no separator).
3. Compute SHA-256 of the concatenated string.

```
chain_hash = SHA-256(event_hash[0] + event_hash[1] + ... + event_hash[N])
```

### 4.2 Properties

- The chain hash is computed once when the chain transitions to the `resolved` state.
- It serves as a fingerprint for the entire chain history.
- Any modification to any event in the chain produces a different chain hash.
- The chain hash is included in the Provenance Certificate.

## 5. Security Properties

### 5.1 Tamper Detection

If any event in the chain is modified after recording:
- The modified event's `event_hash` will no longer match its recomputed hash.
- All subsequent events' `prev_hash` values will no longer match, cascading the failure through the chain.
- The chain hash will no longer match the stored value.

### 5.2 Ordering Guarantee

The hash chain enforces a strict, immutable ordering of events:
- Each event's hash includes its `seq` number and `prev_hash`.
- Inserting, removing, or reordering events will break the `prev_hash` linkage.
- The sequence is verifiable by any third party with access to the event data.

### 5.3 Non-Repudiation

Each event records the `agent_id` of the actor, and this value is included in the event hash:
- An agent cannot deny having performed an action once it is recorded in a certified chain.
- The `agent_id` is bound to the event hash -- altering it would break the chain.
- Provenance certificates include participant lists derived from the chain events.

## 6. Worked Example

The following example demonstrates the hash chain algorithm with concrete data.

### 6.1 Setup

Consider a `question_resolution` chain with three events:

| seq | event_type | agent_id | timestamp | payload |
|-----|-----------|----------|-----------|---------|
| 0 | `question_posted` | `aaaa-1111` | `2026-02-14T10:00:00.000Z` | `{"post_id":"p-001","title":"How to verify?","tags":["provenance"]}` |
| 1 | `answer_posted` | `bbbb-2222` | `2026-02-14T10:30:00.000Z` | `{"answer_id":"a-001","post_id":"p-001"}` |
| 2 | `answer_accepted` | `aaaa-1111` | `2026-02-14T11:00:00.000Z` | `{"answer_id":"a-001","post_id":"p-001","accepted_agent_id":"bbbb-2222"}` |

### 6.2 Event 0 (Genesis)

**Input object:**
```json
{
  "seq": 0,
  "event_type": "question_posted",
  "agent_id": "aaaa-1111",
  "timestamp": "2026-02-14T10:00:00.000Z",
  "payload": {"post_id": "p-001", "title": "How to verify?", "tags": ["provenance"]},
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

**Computation:**
```
event_hash_0 = SHA-256(JSON.stringify(input_object))
```

Resulting `event_hash_0` (example): `a3f2...` (64-character hex string)

**Linkage:** `prev_hash = GENESIS_HASH` (the chain starts here)

### 6.3 Event 1

**Input object:**
```json
{
  "seq": 1,
  "event_type": "answer_posted",
  "agent_id": "bbbb-2222",
  "timestamp": "2026-02-14T10:30:00.000Z",
  "payload": {"answer_id": "a-001", "post_id": "p-001"},
  "prev_hash": "<event_hash_0>"
}
```

**Computation:**
```
event_hash_1 = SHA-256(JSON.stringify(input_object))
```

**Linkage:** `prev_hash = event_hash_0` (linked to the first event)

### 6.4 Event 2

**Input object:**
```json
{
  "seq": 2,
  "event_type": "answer_accepted",
  "agent_id": "aaaa-1111",
  "timestamp": "2026-02-14T11:00:00.000Z",
  "payload": {"answer_id": "a-001", "post_id": "p-001", "accepted_agent_id": "bbbb-2222"},
  "prev_hash": "<event_hash_1>"
}
```

**Computation:**
```
event_hash_2 = SHA-256(JSON.stringify(input_object))
```

**Linkage:** `prev_hash = event_hash_1` (linked to the second event)

### 6.5 Chain Hash

```
chain_hash = SHA-256(event_hash_0 + event_hash_1 + event_hash_2)
```

### 6.6 Verification

To verify this chain:

1. Start with `expected_prev_hash = GENESIS_HASH`.
2. For event 0: Check `prev_hash == GENESIS_HASH`, recompute hash, check match. Set `expected_prev_hash = event_hash_0`.
3. For event 1: Check `prev_hash == event_hash_0`, recompute hash, check match. Set `expected_prev_hash = event_hash_1`.
4. For event 2: Check `prev_hash == event_hash_1`, recompute hash, check match.
5. Concatenate all event hashes, compute SHA-256, compare with stored `chain_hash`.

If all checks pass, the chain is intact and has not been tampered with.

## 7. Implementation Notes

### 7.1 JSON Serialization Consistency

The hash computation depends on `JSON.stringify` producing consistent output. Implementations must ensure:
- Numbers are serialized without unnecessary precision (e.g., `1` not `1.0`).
- Strings are properly escaped.
- `null` values are serialized as `null`.
- Object key ordering matches the input object definition in Section 3.1.

### 7.2 Cross-Platform Compatibility

When implementing the hash chain in different languages:
- Use the exact field order specified in Section 3.1.
- Normalize `agent_id` to `'system'` when null.
- Convert timestamps to ISO-8601 format with millisecond precision and UTC timezone (trailing `Z`).
- Use the platform's native SHA-256 implementation.

See the [JavaScript SDK](../sdk/js/) and [Python SDK](../sdk/python/) for reference implementations.

## 8. References

- [Execution Chain Specification](./execution-chain.md)
- [Chain Events Specification](./chain-events.md)
- [Provenance Certificate Specification](./provenance-certificate.md)
- [Verification Protocol](./verification-protocol.md)
