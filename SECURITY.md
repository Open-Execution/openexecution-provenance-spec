# Security Policy

## Cryptographic Architecture

OpenExecution Provenance uses a three-layer cryptographic accountability model. All cryptographic primitives are industry-standard, NIST-approved algorithms implemented via the Node.js native `crypto` module (OpenSSL backend). No custom or novel cryptographic constructions are used.

For detailed algorithm compliance with international standards (BSI TR-02102, CRYPTREC, NIST, ANSSI, SOG-IS), see [CRYPTOGRAPHIC-COMPLIANCE.md](CRYPTOGRAPHIC-COMPLIANCE.md).

### Core Primitives

| Layer | Algorithm | Standard | Purpose |
|-------|-----------|----------|---------|
| L2: Hash Chain | SHA-256 | FIPS 180-4 | Tamper-evident event linking |
| L3: Signatures | Ed25519 | RFC 8032 / FIPS 186-5 | Certificate signing, non-repudiation |
| Serialization | JCS | RFC 8785 | Deterministic JSON for hash consistency |

### Security Properties

- **Tamper evidence**: Altering any single event in a hash chain invalidates all subsequent hashes
- **Non-repudiation**: Ed25519 asymmetric signatures ensure the signer cannot deny issuance
- **Third-party verifiability**: Anyone can verify certificates using the published public key
- **Timing-safe comparison**: All HMAC verifications use `crypto.timingSafeEqual()`
- **No platform trust required**: Verification is independent of the platform operator

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x (current) | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in the OpenExecution Provenance Specification or its reference implementations, please report it responsibly.

### How to Report

**Email**: security@openexecution.dev

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours of receipt
- **Initial assessment**: Within 7 days
- **Resolution timeline**: Depends on severity; critical issues will be prioritized

### Scope

This security policy covers:
- The provenance specification documents (`spec/`)
- The JavaScript verification SDK (`sdk/js/`)
- The Python verification SDK (`sdk/python/`)
- Cryptographic algorithm implementations referenced in the specification

### Out of Scope

- The OpenExecution Platform (separate repository, separate security policy)
- The OpenExecution Sovereign layer (proprietary, separate security policy)
- Third-party dependencies (report to the respective maintainers)

## Security Design Principles

1. **Record-only**: OpenExecution observes and records. It never creates or modifies external resources.
2. **Cryptographic minimalism**: Only three primitives form the Minimal Verifiable Loop (MVL). Removing any one breaks the verification loop.
3. **Algorithm agility**: The pluggable `CryptoEngine` allows algorithm substitution without breaking existing chains.
4. **Defense in depth**: Multiple independent verification checks (signature validity, chain hash, event integrity) must all pass.
5. **No secrets in verification**: Certificate verification requires only the public key, which is published openly.
