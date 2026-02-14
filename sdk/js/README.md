# @openexecution/verify

Independent verification SDK for OpenExecution Provenance Certificates -- the cryptographic standard for autonomous agent accountability.

Verify Ed25519-signed provenance certificates, SHA-256 hash chains, and chain integrity without any platform cooperation. Anyone verifies with the public key. No shared secrets. No platform trust required.

## Installation

```bash
npm install @openexecution/verify
```

## Quick Start

```javascript
const { OpenExecutionVerifier } = require('@openexecution/verify');

async function main() {
  const verifier = new OpenExecutionVerifier();

  // Verify a certificate via the API
  const result = await verifier.verifyCertificate('certificate-uuid-here');
  console.log(result.valid ? 'VALID' : 'INVALID');
}

main();
```

## API

### `new OpenExecutionVerifier(options?)`

Creates a new verifier instance.

- `options.apiUrl` (string, optional): Base URL for the OpenExecution API. Defaults to `https://api.openexecution.dev/api/v1`.

### `verifier.verifyCertificate(certificateId)`

Verifies a provenance certificate via the OpenExecution API. Returns a `VerificationResult` object containing `valid`, `signature_valid`, `chain_hash_valid`, `certificate`, `chain`, and `integrity` fields.

### `OpenExecutionVerifier.verifySignatureOffline(certificateData, signature, publicKey)`

Verifies a certificate signature offline using Ed25519 public key verification. Requires only the platform's published public key -- no shared secrets needed. Returns `true` if the signature is valid.

### `OpenExecutionVerifier.verifyChainIntegrity(events)`

Verifies the integrity of a hash chain given an array of chain events. Returns an object with `is_valid`, `event_count`, and `errors` fields.

### `OpenExecutionVerifier.computeChainHash(eventHashes)`

Computes the chain hash from an array of event hash strings. Returns a SHA-256 hex digest.

## TypeScript

TypeScript type definitions are included. Import types from the package:

```typescript
import { OpenExecutionVerifier, VerificationResult, ChainEvent } from '@openexecution/verify';
```

## Why Independent Verification Matters

Observability tools (LangSmith, LangFuse, Helicone) produce internal debug records the operator controls. OpenExecution produces Ed25519-signed certificates that anyone can verify independently -- auditors, courts, regulators, counterparties. This SDK enables that independent verification.

Ed25519 satisfies eIDAS "advanced electronic signature" requirements and China's Electronic Signature Law (Article 13), making verified certificates admissible as court-ready evidence.

## Documentation

- [Verification Protocol](https://github.com/openexecution/provenance-spec/blob/main/spec/verification-protocol.md)
- [Hash Chain Algorithm](https://github.com/openexecution/provenance-spec/blob/main/spec/hash-chain.md)
- [Full API Documentation](https://openexecution.dev/docs)

## License

Apache-2.0
