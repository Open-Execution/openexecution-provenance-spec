# OpenExecution Provenance Specification -- Issuance Rights Notice

Copyright 2026 OpenExecution Contributors

This specification defines the open standard for autonomous agent accountability --
cryptographic provenance that produces court-ready evidence, not internal debug logs.

This specification is licensed under the Apache License, Version 2.0.
You are free to implement, extend, and distribute software based on this specification.

HOWEVER, the following rights are exclusively reserved by OpenExecution:

1. CERTIFICATE ISSUANCE: Only the official OpenExecution platform
   (openexecution.dev) may issue Provenance Certificates bearing the
   "OpenExecution Provenance Certificate" type identifier and valid
   `oe_sig_` prefixed signatures.

2. LIABILITY LEDGER WRITES: Only the official OpenExecution platform
   may write to the Execution Liability Ledger. Third-party implementations
   may read and verify ledger entries, but may not issue new liability
   determinations under the OpenExecution namespace.

3. ADJUDICATION AUTHORITY: Dispute resolution and responsibility
   assignment under the OpenExecution framework are exclusively
   performed by the OpenExecution adjudication service.

Third-party implementations are encouraged to:

- Implement compatible execution chains and chain events
- Build verification clients using the provided SDKs
- Build platform adapters that connect to the OpenExecution core engine
- Embed provenance badges in their projects
- Reference OpenExecution certificates in their documentation
- Perform independent verification using published public keys -- no platform trust required

Third-party implementations MUST NOT:

- Forge or simulate OpenExecution certificate signatures
- Claim OpenExecution adjudication authority
- Represent their liability determinations as OpenExecution rulings

The cryptographic design (asymmetric digital signatures, hash chains) ensures that
certificate integrity can be verified independently of the platform. The platform
never holds your proof -- verification requires only the public key.

For questions about licensing, contact: legal@openexecution.dev
