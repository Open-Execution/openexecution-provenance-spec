# Cryptographic Compliance Statement

**OpenExecution Provenance Specification**
**Document Version**: 1.0
**Date**: 2026-03-11
**Specification**: OpenExecution Provenance v1 (Apache 2.0 + Issuance Rights)

This document declares the cryptographic algorithms used by the OpenExecution Provenance Specification and their compliance status with international and national cryptographic standards bodies.

---

## Cryptographic Primitives Summary

The OpenExecution Provenance system implements the **Minimal Verifiable Loop (MVL)** architecture defined in the AEGIS (Agent Execution Governance and Integrity Standard) paper (Li, 2026, Section 6.5). The MVL consists of exactly three cryptographic roles:

| Role | Algorithm | Standard | Security Level | Purpose |
|------|-----------|----------|----------------|---------|
| **Hash Function** | SHA-256 (default) | NIST FIPS 180-4 | 128-bit | Tamper detection via hash chain |
| **Hash Function** | SHA-384 | NIST FIPS 180-4 | 192-bit | Higher-security hash chain |
| **Hash Function** | SHA-512 | NIST FIPS 180-4 | 256-bit | Maximum SHA-2 security margin |
| **Hash Function** | SHA3-256 | NIST FIPS 202 | 128-bit | Keccak-based alternative hash |
| **Hash Function** | SHA3-384 | NIST FIPS 202 | 192-bit | Keccak-based higher-security hash |
| **Hash Function** | SHA3-512 | NIST FIPS 202 | 256-bit | Keccak-based maximum-security hash |
| **Digital Signature** | Ed25519 (default) | RFC 8032, FIPS 186-5 | 128-bit | Non-repudiation, certificate signing |
| **Digital Signature** | Ed448 | RFC 8032, FIPS 186-5 | 224-bit | Higher-security EdDSA variant |
| **Digital Signature** | ECDSA P-256 | FIPS 186-4/186-5 (prime256v1) | 128-bit | NIST curve ECDSA signatures |
| **Digital Signature** | ECDSA P-384 | FIPS 186-4/186-5 (secp384r1) | 192-bit | NIST curve ECDSA signatures |
| **Digital Signature** | ECDSA P-521 | FIPS 186-4/186-5 (secp521r1) | 256-bit | NIST curve ECDSA signatures |
| **Canonicalization** | JCS (JSON Canonicalization Scheme) | RFC 8785 | N/A | Deterministic serialization for hash consistency |

The pluggable `CryptoEngine` supports **30 provider combinations** (6 hash algorithms x 5 signature algorithms x 1 canonicalization scheme).

Additional cryptographic primitives used in the platform layer:

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| AES-256-GCM | NIST SP 800-38D | API key encryption at rest |
| scrypt | RFC 7914 | Key derivation for encryption vault |
| HMAC-SHA256 | RFC 2104 / FIPS 198-1 | Webhook signature verification |
| bcrypt | OpenBSD bcrypt | Password hashing (cost factor 12) |
| HS256 (HMAC-SHA256) | RFC 7519 | JWT session tokens |

**Implementation**: All cryptographic operations use the Node.js native `crypto` module (backed by OpenSSL/BoringSSL), with no custom or novel cryptographic constructions. The contribution of this project is architectural (three-layer accountability for autonomous agents), not cryptographic.

---

## BSI TR-02102 Compliance (Germany)

**Reference**: BSI Technical Guideline TR-02102-1, Version 2026-01
**Authority**: Bundesamt fur Sicherheit in der Informationstechnik (Federal Office for Information Security, Germany)

The BSI TR-02102-1 provides recommendations for cryptographic algorithms and key lengths for use in German federal IT systems. All algorithms used by OpenExecution Provenance are listed as **recommended** or **acceptable** in the current guideline.

### Compliance Matrix

| Algorithm | BSI TR-02102-1 Status | Section | Notes |
|-----------|----------------------|---------|-------|
| **SHA-256** | Recommended | 4.2 | Recommended for all applications; minimum 2028+ |
| **SHA-384** | Recommended | 4.2 | Recommended for all applications |
| **SHA-512** | Recommended | 4.2 | Recommended for all applications |
| **SHA3-256** | Recommended | 4.2 | Keccak-based; recommended for all applications |
| **SHA3-384** | Recommended | 4.2 | Keccak-based; recommended for all applications |
| **SHA3-512** | Recommended | 4.2 | Keccak-based; recommended for all applications |
| **Ed25519** (Curve25519) | Recommended | 4.3 | EdDSA on Curve25519; recommended for digital signatures |
| **Ed448** (Curve448) | Recommended | 4.3 | EdDSA on Curve448; recommended for higher-security digital signatures |
| **ECDSA P-256** (prime256v1) | Recommended | 4.3 | NIST curve; recommended for digital signatures |
| **ECDSA P-384** (secp384r1) | Recommended | 4.3 | NIST curve; recommended for digital signatures |
| **ECDSA P-521** (secp521r1) | Recommended | 4.3 | NIST curve; recommended for digital signatures |
| **AES-256** (GCM mode) | Recommended | 3.2, 3.5 | 256-bit key length exceeds minimum requirement of 128 bits; GCM is an approved mode of operation |
| **HMAC-SHA256** | Recommended | 4.4 | Recommended for message authentication |
| **scrypt** | Acceptable | 4.5 | Recognized memory-hard KDF |
| **bcrypt** | Not listed | N/A | Password hashing; not in BSI scope (non-standard KDF) |

### Post-Quantum Readiness

BSI TR-02102-1 (2026-01) includes guidance on migration to post-quantum cryptography. OpenExecution's pluggable `CryptoEngine` architecture supports algorithm substitution without breaking existing chains: each chain records its `crypto_provider` identifier, enabling migration to post-quantum signature schemes (e.g., ML-DSA/Dilithium) when standardized.

---

## CRYPTREC Compliance (Japan)

**Reference**: CRYPTREC Ciphers List (e-Government Recommended Ciphers List), May 2024 revision
**Authority**: Cryptography Research and Evaluation Committees (CRYPTREC), operated jointly by NICT and IPA under the Japanese Ministry of Internal Affairs and Communications

The CRYPTREC Ciphers List classifies algorithms into three categories:
- **E-Government Recommended**: Actively recommended for government systems
- **Candidate Recommended**: Acceptable alternatives
- **Monitoring**: Deprecated but monitored

### Compliance Matrix

| Algorithm | CRYPTREC Status | Category | Notes |
|-----------|----------------|----------|-------|
| **SHA-256** | E-Government Recommended | Hash function | Listed in the recommended hash function category |
| **SHA-384** | E-Government Recommended | Hash function | Listed in the recommended hash function category |
| **SHA-512** | E-Government Recommended | Hash function | Listed in the recommended hash function category |
| **SHA3-256** | E-Government Recommended | Hash function | Keccak-based; listed in recommended hash functions |
| **SHA3-384** | E-Government Recommended | Hash function | Keccak-based; listed in recommended hash functions |
| **SHA3-512** | E-Government Recommended | Hash function | Keccak-based; listed in recommended hash functions |
| **Ed25519** (EdDSA) | Candidate Recommended | Digital signature | EdDSA listed as candidate/recommended signature scheme |
| **Ed448** (EdDSA) | Candidate Recommended | Digital signature | EdDSA on Curve448; candidate/recommended |
| **ECDSA P-256** (prime256v1) | E-Government Recommended | Digital signature | NIST prime curve; recommended for signatures |
| **ECDSA P-384** (secp384r1) | E-Government Recommended | Digital signature | NIST prime curve; recommended for signatures |
| **ECDSA P-521** (secp521r1) | Candidate Recommended | Digital signature | NIST prime curve; candidate recommended |
| **AES-256** (GCM) | E-Government Recommended | Authenticated encryption | AES with 128/192/256-bit keys; GCM mode approved |
| **HMAC-SHA256** | E-Government Recommended | Message authentication | HMAC with SHA-256 core |

---

## NIST Standards Compliance (United States)

**Authority**: National Institute of Standards and Technology (NIST), U.S. Department of Commerce

### Algorithm Standards Compliance

| Algorithm | NIST Standard | Status | Notes |
|-----------|---------------|--------|-------|
| **SHA-256** | FIPS 180-4 (SHS) | Approved | Secure Hash Standard; approved for all federal applications |
| **SHA-384** | FIPS 180-4 (SHS) | Approved | Secure Hash Standard; approved for all federal applications |
| **SHA-512** | FIPS 180-4 (SHS) | Approved | Secure Hash Standard; approved for all federal applications |
| **SHA3-256** | FIPS 202 | Approved | Keccak-based hash; approved for all federal applications |
| **SHA3-384** | FIPS 202 | Approved | Keccak-based hash; approved for all federal applications |
| **SHA3-512** | FIPS 202 | Approved | Keccak-based hash; approved for all federal applications |
| **Ed25519** | FIPS 186-5 (DSS) | Approved | Digital Signature Standard; EdDSA added in FIPS 186-5 (2023) |
| **Ed448** | FIPS 186-5 (DSS) | Approved | EdDSA on Curve448; added in FIPS 186-5 (2023) |
| **ECDSA P-256** (prime256v1) | FIPS 186-4/186-5 (DSS) | Approved | NIST prime curve; approved for digital signatures |
| **ECDSA P-384** (secp384r1) | FIPS 186-4/186-5 (DSS) | Approved | NIST prime curve; approved for digital signatures |
| **ECDSA P-521** (secp521r1) | FIPS 186-4/186-5 (DSS) | Approved | NIST prime curve; approved for digital signatures |
| **AES-256-GCM** | FIPS 197 + SP 800-38D | Approved | AES (FIPS 197) in GCM mode (SP 800-38D) |
| **HMAC-SHA256** | FIPS 198-1 | Approved | Keyed-Hash Message Authentication Code |
| **scrypt** | RFC 7914 | Not NIST-specified | Memory-hard KDF for key derivation |

### CAVP Readiness

The OpenExecution cryptographic implementation uses exclusively NIST-approved algorithms via the Node.js `crypto` module (OpenSSL backend). All algorithms are eligible for NIST CAVP (Cryptographic Algorithm Validation Program) testing. Formal CAVP algorithm validation certificates are planned for a future phase.

---

## ANSSI Compliance (France)

**Reference**: ANSSI Referentiel General de Securite (RGS), Annexe B1
**Authority**: Agence nationale de la securite des systemes d'information (National Cybersecurity Agency of France)

| Algorithm | ANSSI RGS Status | Notes |
|-----------|-----------------|-------|
| **SHA-256** | Recommended | Minimum recommended hash function |
| **SHA-384** | Recommended | Recommended for higher security margins |
| **SHA-512** | Recommended | Recommended for higher security margins |
| **SHA3-256** | Recommended | Keccak-based; recommended hash function |
| **SHA3-384** | Recommended | Keccak-based; recommended for higher security |
| **SHA3-512** | Recommended | Keccak-based; recommended for maximum security |
| **Ed25519** | Acceptable | EdDSA on recommended curves |
| **Ed448** | Acceptable | EdDSA on Curve448; acceptable for signatures |
| **ECDSA P-256** (prime256v1) | Recommended | NIST prime curve; recommended for signatures |
| **ECDSA P-384** (secp384r1) | Recommended | NIST prime curve; recommended for signatures |
| **ECDSA P-521** (secp521r1) | Recommended | NIST prime curve; recommended for signatures |
| **AES-256** | Recommended | 256-bit exceeds the 128-bit minimum |
| **HMAC-SHA256** | Recommended | Standard MAC construction |

---

## SOG-IS Compliance (European Union)

**Reference**: SOG-IS Crypto Evaluation Scheme, Agreed Cryptographic Mechanisms v1.3
**Authority**: Senior Officials Group Information Systems Security (SOG-IS), representing 17 EU member states

| Algorithm | SOG-IS Status | Notes |
|-----------|--------------|-------|
| **SHA-256** | Agreed mechanism | Approved for use in evaluated products |
| **SHA-384** | Agreed mechanism | Approved for use in evaluated products |
| **SHA-512** | Agreed mechanism | Approved for use in evaluated products |
| **SHA3-256** | Agreed mechanism | Keccak-based; approved for evaluated products |
| **SHA3-384** | Agreed mechanism | Keccak-based; approved for evaluated products |
| **SHA3-512** | Agreed mechanism | Keccak-based; approved for evaluated products |
| **Ed25519** | Agreed mechanism | EdDSA on Curve25519; approved |
| **Ed448** | Agreed mechanism | EdDSA on Curve448; approved |
| **ECDSA P-256** (prime256v1) | Agreed mechanism | NIST prime curve; approved for signatures |
| **ECDSA P-384** (secp384r1) | Agreed mechanism | NIST prime curve; approved for signatures |
| **ECDSA P-521** (secp521r1) | Agreed mechanism | NIST prime curve; approved for signatures |
| **AES-256-GCM** | Agreed mechanism | AES in authenticated encryption mode; approved |

---

## Legal Framework Alignment

### EU AI Act (Regulation 2024/1689)

The OpenExecution Provenance architecture addresses the following EU AI Act requirements:

| Article | Requirement | OE Coverage |
|---------|------------|-------------|
| Art. 12 | Automatic logging of high-risk AI system operations | L1 behavior recording + L2 hash chain |
| Arts. 19, 26 | Retention of logs for at least 6 months | Hash chain designed for long-term storage integrity |
| Art. 14 | Human oversight capability | Structured event schema with human-readable payloads |
| Art. 73 | Incident reporting within 2-15 days | Provenance certificates enable rapid incident reconstruction |

### eIDAS Regulation (EU 910/2014)

All supported digital signature algorithms (Ed25519, Ed448, ECDSA P-256/P-384/P-521) satisfy the requirements for **advanced electronic signatures** under eIDAS Article 26:
- Uniquely linked to the signatory (platform-held private key)
- Capable of identifying the signatory (public key fingerprint in certificate)
- Created using data under the signatory's sole control (HSM-backed or platform custody)
- Linked to the signed data such that any subsequent change is detectable (hash chain integrity)

### China Electronic Signature Law (Article 13)

Ed25519 signatures are compatible with the requirements of China's Electronic Signature Law, Article 13, which recognizes electronic signatures that are under the exclusive control of the signatory and linked to the signed data.

---

## Implementation Details

### Pluggable Cryptographic Architecture

OpenExecution implements a pluggable `CryptoEngine` that separates algorithm selection from business logic:

```
CryptoEngine({
  hashAlgorithm:     'sha256',    // FIPS 180-4 — or sha384, sha512, sha3-256, sha3-384, sha3-512
  signatureAlgorithm: 'ed25519',  // RFC 8032   — or ed448, ecdsa-p256, ecdsa-p384, ecdsa-p521
  canonicalization:   'jcs'       // RFC 8785
})
```

**Supported hash algorithms (6)**: SHA-256, SHA-384, SHA-512 (FIPS 180-4); SHA3-256, SHA3-384, SHA3-512 (FIPS 202)
**Supported signature algorithms (5)**: Ed25519, Ed448 (RFC 8032); ECDSA P-256, ECDSA P-384, ECDSA P-521 (FIPS 186-4/186-5)
**Supported canonicalization (1)**: JCS (RFC 8785)

Each provenance chain records its `crypto_provider` identifier at creation time. This design enables:
- **Algorithm agility**: New algorithms can be added without breaking existing chains
- **Regulatory flexibility**: Different jurisdictions can mandate different algorithm suites
- **Post-quantum migration**: Chains can adopt ML-DSA/Dilithium when NIST finalizes PQC standards

### Available Provider Configurations

The CryptoEngine supports **30 provider combinations** (6 hash algorithms x 5 signature algorithms x 1 canonicalization scheme). Provider IDs follow the naming convention `MVL_{hash}_{signature}_JCS`. Representative configurations:

| Provider ID | Hash | Signature | Canonicalization |
|---|---|---|---|
| `MVL_SHA256_Ed25519_JCS` | SHA-256 (FIPS 180-4) | Ed25519 (RFC 8032) | JCS (RFC 8785) |
| `MVL_SHA384_Ed25519_JCS` | SHA-384 (FIPS 180-4) | Ed25519 (RFC 8032) | JCS (RFC 8785) |
| `MVL_SHA512_Ed25519_JCS` | SHA-512 (FIPS 180-4) | Ed25519 (RFC 8032) | JCS (RFC 8785) |
| `MVL_SHA3256_Ed25519_JCS` | SHA3-256 (FIPS 202) | Ed25519 (RFC 8032) | JCS (RFC 8785) |
| `MVL_SHA3384_Ed25519_JCS` | SHA3-384 (FIPS 202) | Ed25519 (RFC 8032) | JCS (RFC 8785) |
| `MVL_SHA3512_Ed25519_JCS` | SHA3-512 (FIPS 202) | Ed25519 (RFC 8032) | JCS (RFC 8785) |
| `MVL_SHA256_Ed448_JCS` | SHA-256 (FIPS 180-4) | Ed448 (RFC 8032) | JCS (RFC 8785) |
| `MVL_SHA256_ECDSAP256_JCS` | SHA-256 (FIPS 180-4) | ECDSA P-256 (FIPS 186-5) | JCS (RFC 8785) |
| `MVL_SHA384_ECDSAP384_JCS` | SHA-384 (FIPS 180-4) | ECDSA P-384 (FIPS 186-5) | JCS (RFC 8785) |
| `MVL_SHA512_ECDSAP521_JCS` | SHA-512 (FIPS 180-4) | ECDSA P-521 (FIPS 186-5) | JCS (RFC 8785) |

All 30 combinations are valid. The table above shows representative pairings; any hash can be combined with any signature algorithm.

### Security Design Patterns

- **Timing-safe comparison**: All HMAC verifications use `crypto.timingSafeEqual()` to prevent timing side-channel attacks
- **Authenticated encryption**: AES-256-GCM provides both confidentiality and integrity (AEAD)
- **Key derivation**: scrypt with memory-hard parameters prevents brute-force attacks on vault keys
- **No custom cryptography**: All primitives are industry-standard implementations via Node.js `crypto` (OpenSSL)

---

## Certification Roadmap

| Phase | Certification | Status | Target |
|-------|--------------|--------|--------|
| 1 | BSI TR-02102 compliance claim | **Complete** | 2026 Q1 |
| 1 | CRYPTREC compliance claim | **Complete** | 2026 Q1 |
| 1 | NIST standards alignment | **Complete** | 2026 Q1 |
| 1 | ANSSI RGS alignment | **Complete** | 2026 Q1 |
| 1 | SOG-IS alignment | **Complete** | 2026 Q1 |
| 2 | OpenSSF Best Practices Badge | Planned | 2026 Q2 |
| 2 | OWASP ASVS v5.0 self-assessment | Planned | 2026 Q2 |
| 3 | NIST CAVP algorithm validation | Planned | Upon funding |
| 3 | ANSSI CSPN certification | Planned | Upon funding |
| 4 | FIPS 140-3 module validation | Planned | Enterprise phase |

---

## References

- NIST FIPS 180-4: Secure Hash Standard (SHS), August 2015
- NIST FIPS 186-4: Digital Signature Standard (DSS), July 2013
- NIST FIPS 186-5: Digital Signature Standard (DSS), February 2023
- NIST FIPS 197: Advanced Encryption Standard (AES), November 2001
- NIST FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC), July 2008
- NIST FIPS 202: SHA-3 Standard, August 2015
- NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: GCM, November 2007
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA), January 2017
- RFC 8785: JSON Canonicalization Scheme (JCS), June 2020
- RFC 7914: The scrypt Password-Based Key Derivation Function, August 2016
- RFC 7519: JSON Web Token (JWT), May 2015
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication, February 1997
- BSI TR-02102-1: Cryptographic Mechanisms: Recommendations and Key Lengths, Version 2026-01
- CRYPTREC: e-Government Recommended Ciphers List, May 2024
- ANSSI RGS: Referentiel General de Securite, Annexe B1
- SOG-IS: Agreed Cryptographic Mechanisms, v1.3
- Li, A. (2026). AEGIS: Agent Execution Governance and Integrity Standard -- A Survey and Reference Architecture for AI Agent Action Accountability. Zenodo. doi:10.5281/zenodo.18955103

---

## Disclaimer

This document constitutes a self-assessed compliance statement based on public algorithm recommendation lists published by the referenced standards bodies. It does not represent formal certification, validation, or endorsement by any listed authority. Formal algorithm validation (e.g., NIST CAVP) and product certification (e.g., ANSSI CSPN, FIPS 140-3) are separate processes documented in the Certification Roadmap above.

The cryptographic implementations referenced in this document are provided by the Node.js `crypto` module backed by OpenSSL. The security of these implementations depends on the underlying OpenSSL version and its own validation status. Organizations with strict compliance requirements should verify the OpenSSL version deployed in their environment against NIST's CMVP validated modules list.
