<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# DigiByte Q-ID Contracts Index

This directory contains **normative, contract-locked specifications** for DigiByte Q-ID.

If **code**, tests, or non-contract documentation conflicts with a contract in this folder, **the contract wins**.

## How to Use These Contracts

- Implementations MUST follow these documents exactly.
- Changes that affect serialization, canonicalization, or verification rules MUST be treated as **consensus-like** changes.
- Contract documents are written to support **independent re-implementation** and **security review**.

## Contract Versioning Rules

- Contract filenames end with `_vN.md`.
- Any **breaking** change MUST create a new version (e.g., `..._v2.md`).
- Older versions remain valid references for compatibility testing and migrations.

## Contracts

### Crypto Envelope v1

- File: `crypto_envelope_v1.md`
- Purpose: Defines the **signature envelope format** used across Q-ID.
- Key properties:
  - Deterministic signing input (canonical JSON bytes)
  - Explicit algorithm identifiers
  - Fail-closed parsing and verification rules

### Hybrid Key Container v1

- File: `hybrid_key_container_v1.md`
- Purpose: Defines the **container format** for hybrid key material (e.g., ML-DSA + Falcon).
- Key properties:
  - Explicit component structure (per-alg public/secret)
  - Verification-time requirements (no missing components)
  - Safe decoding behavior (fail-closed)

## Suggested Next Contracts

These are the next âcontract surfaceâ candidates once the current two are stable:

- **QID URI Scheme v1** (`qid_uri_scheme_v1.md`): canonical encoding/decoding rules for `qid://...`
- **Registration Payload v1** (`registration_payload_v1.md`): required fields + validation rules
- **Login Request/Response Payload v1** (`login_payloads_v1.md`): required fields + nonce binding rules

---

**Author:** DarekDGB  
**License:** MIT (2025)
