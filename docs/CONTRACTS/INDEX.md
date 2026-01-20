<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# DigiByte Q-ID Contracts Index

This directory contains **normative, contract-locked specifications** for DigiByte Q-ID.

If **code**, tests, examples, or non-contract documentation conflict with any document
in this directory, **the contract wins**.

---

## Purpose of This Directory

The documents in `docs/CONTRACTS/` define the **stable, security-critical interface**
of DigiByte Q-ID.

They are written to:
- support **independent re-implementation**
- enable **formal security review**
- prevent accidental or silent breaking changes

This directory represents the **contract boundary** of the system.

---

## How to Use These Contracts

- Implementations **MUST** follow these documents exactly.
- Parsing, canonicalization, and verification rules are **fail-closed by default**.
- Any change affecting serialized formats or verification logic must be treated as
  **consensus-like**.

---

## Contract Versioning Rules

- Contract filenames end with `_vN.md`
- Any **breaking change** requires a new version (e.g. `_v2.md`)
- Older versions remain valid references for:
  - compatibility testing
  - migration tooling
  - historical audit

---

## Active Contracts

### Crypto Envelope v1

- File: `crypto_envelope_v1.md`
- Purpose: Defines the **signature envelope format** used across DigiByte Q-ID.
- Key properties:
  - Canonical JSON signing input
  - Explicit algorithm identifiers
  - Fail-closed decoding and verification
  - No silent fallback or downgrade

---

### Hybrid Key Container v1

- File: `hybrid_key_container_v1.md`
- Purpose: Defines the **container format** for hybrid key material
  (e.g. ML-DSA + Falcon).
- Key properties:
  - Explicit per-algorithm components
  - Strict presence requirements
  - Safe decoding (fail-closed)
  - Designed for PQC hybrid verification

---

### Protocol Messages v1

- File: `protocol_messages_v1.md`
- Purpose: Defines **high-level Q-ID protocol messages**.
- Covers:
  - Login request payloads
  - Login response payloads
  - Registration payloads
- Key properties:
  - Nonce binding
  - Context separation
  - Deterministic serialization rules

---

### QID URI Scheme v1

- File: `qid_uri_scheme_v1.md`
- Purpose: Defines the canonical `qid://` URI format.
- Key properties:
  - Deterministic encoding
  - Explicit action routing
  - Safe parsing rules
  - No ambiguous parameters

---

## Non-Contract Documentation

Documents **outside** this directory:
- MAY explain usage or examples
- MUST NOT redefine or override any rule here
- MUST defer to contracts in case of conflict

---

**Author:** DarekDGB  
**License:** MIT (2025)
