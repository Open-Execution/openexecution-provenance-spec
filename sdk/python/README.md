# openexecution-verify

Independent verification SDK for OpenExecution Provenance Certificates -- the cryptographic standard for autonomous agent accountability.

Verify Ed25519-signed provenance certificates, SHA-256 hash chains, and chain integrity without any platform cooperation. Anyone verifies with the public key. No shared secrets. No platform trust required.

## Installation

```bash
pip install openexecution-verify
```

## Quick Start

```python
from openexecution_verify import OpenExecutionVerifier

verifier = OpenExecutionVerifier()

# Verify a certificate via the API
result = verifier.verify_certificate("certificate-uuid-here")
print("VALID" if result.get("valid") else "INVALID")
```

## API

### `OpenExecutionVerifier(api_url=None)`

Creates a new verifier instance.

- `api_url` (str, optional): Base URL for the OpenExecution API. Defaults to `https://api.openexecution.dev/api/v1`.

### `verifier.verify_certificate(certificate_id)`

Verifies a provenance certificate via the OpenExecution API. Returns a dictionary containing `valid`, `signature_valid`, `chain_hash_valid`, `certificate`, `chain`, and `integrity` fields.

### `OpenExecutionVerifier.verify_signature_offline(certificate_data, signature, public_key)`

Verifies a certificate signature offline using Ed25519 public key verification. Requires only the platform's published public key -- no shared secrets needed. Returns `True` if the signature is valid.

### `OpenExecutionVerifier.verify_chain_integrity(events)`

Verifies the integrity of a hash chain given a list of chain event dictionaries. Returns a dictionary with `is_valid`, `event_count`, and `errors` fields.

### `OpenExecutionVerifier.compute_chain_hash(event_hashes)`

Computes the chain hash from a list of event hash strings. Returns a SHA-256 hex digest.

## Why Independent Verification Matters

Observability tools (LangSmith, LangFuse, Helicone) produce internal debug records the operator controls. OpenExecution produces Ed25519-signed certificates that anyone can verify independently -- auditors, courts, regulators, counterparties. This SDK enables that independent verification.

Ed25519 satisfies eIDAS "advanced electronic signature" requirements and China's Electronic Signature Law (Article 13), making verified certificates admissible as court-ready evidence.

## Documentation

- [Verification Protocol](https://github.com/openexecution/provenance-spec/blob/main/spec/verification-protocol.md)
- [Hash Chain Algorithm](https://github.com/openexecution/provenance-spec/blob/main/spec/hash-chain.md)
- [Full API Documentation](https://openexecution.dev/docs)

## License

Apache-2.0
