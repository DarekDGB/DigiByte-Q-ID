<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# SECURITY POLICY

## DigiByte Q-ID - v1.1.0

---

## Security Philosophy

Q-ID is built on strict, non-negotiable principles:

- Fail-closed by default
- Deterministic behavior only
- No silent fallback
- Explicit cryptographic intent
- Test-locked guarantees

If something is uncertain -> it must FAIL.

---

## Core Security Guarantees

### 1. Fail-Closed Enforcement
All verification paths MUST:

- Reject invalid input
- Reject malformed payloads
- Reject missing fields
- Reject unexpected structures

No recovery paths.
No soft failures.
No partial success.

### 2. Deterministic Canonicalization

Security-critical serialization uses the named profiles implemented in
`qid/canonical_profiles.py`:

- `qid-canonical-json-v1` for internal Q-ID signing and verification bytes;
- `adamantine-qid-canonical-json-v1` for the AdamantineOS proof-hash boundary.

`qid.canonical.canonical_json_bytes` is the shared internal Q-ID helper.
The integration profile deliberately escapes non-ASCII characters.

This ensures:

- identical signing and verification bytes
- no cross-module drift
- stable hashing and binding IDs

Any deviation is considered a security violation.

### 3. No Silent Fallback

If a cryptographic backend is required:

- It MUST exist
- It MUST be used
- If unavailable -> FAIL

Never fallback silently to stub or alternative logic.

### 4. PQC Backend Rules

Default mode:
- Stub (CI-safe), a development scaffold that is not secure PQC.

Optional real PQC:

    QID_PQC_BACKEND=liboqs
    QID_PQC_TESTS=1

Rules:
- Explicit opt-in only
- Backend must be present
- Missing backend -> FAIL
- `QID_PQC_TESTS=1` opts tests in; runtime selection remains explicit.
- Current Q-ID runtime mappings use ML-DSA-44 and Falcon-512. Shield's
  ML-DSA-65 and draft FN-DSA/Falcon-1024 profiles are a separate boundary.

### 5. Hybrid Signature Enforcement

Hybrid mode = strict AND

- ML-DSA must verify
- Falcon must verify
- Any failure -> full rejection

No downgrade allowed.

### 6. Signature Integrity

- Payload must be signed exactly as verified
- No transformation allowed between sign and verify
- Canonical bytes must match exactly

### 7. Guardian Wallet v3 Auth Bridge

Q-ID v1.1.0 adds a deterministic auth bridge for Guardian Wallet v3.

Security boundary:
- Q-ID verifies identity and binding facts
- Guardian Wallet v3 evaluates policy
- auth is not forced into transaction semantics

Bridge requests must:
- reject unknown keys fail-closed
- reject malformed optional auth fields fail-closed
- preserve deterministic request shape
- preserve explicit responsibility boundaries

---

## Threat Model

Q-ID is designed to resist:

- serialization inconsistencies
- replay attacks (nonce-based flows)
- signature tampering
- downgrade attacks
- partial verification bypass
- backend misconfiguration
- auth-bridge schema drift

Services must supply nonce issuance, replay state, key handling, and deployment
policy. Passing tests or nonce validation alone does not establish a durable
replay store, production readiness, or a security certification.

---

## Explicit Non-Goals

Q-ID does NOT:

- provide a private-key custody service (APIs can handle caller-supplied secret
  key material and hybrid containers)
- auto-select cryptographic backends
- perform implicit recovery
- make Guardian policy decisions internally
- verify Shield cryptography or grant execution authority
- sign or broadcast DigiByte transactions

The [frozen compatibility contract](docs/CONTRACTS/QID_SHIELD_V4_CRYPTO_ALIGNMENT.md)
keeps identity keys, Shield decision keys, trust registries, profiles, domain
tags, and verifier policy separate. AdamantineOS remains the final fail-closed
policy and execution boundary. Neither matching algorithm names nor a valid
Q-ID proof can override a Shield denial or AdamantineOS policy.

---

## Security Validation

Security is enforced through:

- 100% statement and branch coverage (CI enforced)
- canonicalization regression tests
- fail-closed path testing
- hybrid verification tests
- PQC backend enforcement tests
- Guardian Wallet v3 auth bridge regression tests

The optional-liboqs workflow has no exact node-ID and zero-skip guard.
A green run alone does not establish that all intended native tests ran.
This policy makes no guarded Q-ID live-OQS, Shield cryptographic proof, final
FIPS 206, production deployment, or key-custody certification claim.

---

## Reporting Vulnerabilities

If you discover a security issue, report it privately:

adamantinewalletos@gmail.com

Please include:

- clear description
- reproduction steps
- impact assessment (if known)

---

## Version Scope

This policy applies to:

- Q-ID v1.1.0
- subsequent hardening releases unless explicitly changed

G1 retains package 1.1.0 without a bump for documentation and tests. Current
working-tree evidence is recorded in
[G1 release truth](docs/RELEASES/V4_10_G1_RELEASE_TRUTH.md); it is distinct from
the existing v1.1.0 tag and does not declare a new release.

---

## Final Principle

Q-ID does not guess.
Q-ID does not fallback.
Q-ID verifies.

---

Copyright (c) DarekDGB
