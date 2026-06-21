# Q-ID / Shield v4 Crypto Alignment

Author attribution: DarekDGB

## Status

This document is a Q-ID-side alignment lock for future Shield v4 PQC integration.

Baseline tag: `ecosystem-pre-v4-audit-lock`

This is not a Shield v4 release. It does not add Shield signing code, Shield verification code, Shield key material, wallet authority, or DigiByte consensus changes.

## Purpose

Q-ID already carries the ecosystem's PQC naming direction and fail-closed crypto model.

Shield v4 may align with that naming direction, but Q-ID keys, Q-ID login proofs, Q-ID identity attestations, Q-ID bindings, and Q-ID trust roles must not become Shield decision authority.

Q-ID proves identity / authentication evidence.

Shield v4 proves Shield component verdict evidence and Shield Orchestrator receipt evidence.

AdamantineOS remains the final execution boundary.

## Non-Negotiable Boundary

Q-ID does not make Shield decisions.

Q-ID does not sign Shield component verdicts.

Q-ID does not sign Shield Orchestrator receipts.

Q-ID does not sign transactions.

Q-ID does not broadcast transactions.

Q-ID does not change DigiByte consensus.

Q-ID does not override AdamantineOS final policy.

A Q-ID proof may be evidence inside a larger AdamantineOS decision, but it must not be interpreted as Shield v4 cryptographic verification.

## Algorithm Naming Reference

Q-ID currently defines this algorithm identifier direction:

| Identifier | Accurate meaning |
|---|---|
| `dev-hmac-sha256` | Development / CI-safe deterministic scaffold only |
| `pqc-ml-dsa` | ML-DSA, formerly CRYSTALS-Dilithium |
| `pqc-falcon` | FN-DSA, based on Falcon |
| `pqc-hybrid-ml-dsa-falcon` | ML-DSA plus FN-DSA/Falcon hybrid with strict AND semantics |

ML-DSA and FN-DSA/Falcon are separate signature directions.

FN-DSA/Falcon must never be described as ML-DSA.

The legacy Q-ID identifier `hybrid-dev-ml-dsa` is a Q-ID compatibility concern only. Shield v4 must not silently inherit legacy Q-ID identifiers without explicit Shield-side compatibility rules.

## Q-ID Files That Inform Naming

The Q-ID source of truth for current algorithm naming and PQC behavior includes:

- `qid/algorithms.py`
- `qid/crypto.py`
- `qid/pqc_backends.py`
- `qid/pqc_sign.py`
- `qid/pqc_verify.py`
- `docs/CONTRACTS/PQC_MODEL.md`
- `docs/CONTRACTS/CANONICAL_JSON_PROFILES.md`

These files may inform Shield v4 naming and failure philosophy.

They do not define Shield v4 key roles, Shield v4 trust registry authority, Shield v4 canonicalization bytes, Shield v4 domain tags, or Shield v4 final verifier policy.

## Key Separation Lock

Q-ID keys must not be reused as Shield v4 keys.

Shield v4 must define its own trust registry and key roles, including:

- `shield_component_adn`
- `shield_component_dqsn`
- `shield_component_guardian_wallet`
- `shield_component_qwg`
- `shield_component_sentinel_ai`
- `shield_orchestrator`

A Q-ID identity key must never be accepted as a Shield component key.

A Q-ID identity key must never be accepted as a Shield Orchestrator key.

A Shield key must never be accepted as a Q-ID identity key.

Key reuse across Q-ID and Shield v4 would create role confusion and must fail closed.

## Trust Role Separation

| Domain | Key role | Evidence meaning |
|---|---|---|
| Q-ID | Identity / authentication key | User or device authentication evidence |
| Shield component | Component decision key | Signed component verdict evidence |
| Shield Orchestrator | Orchestrator aggregation key | Signed final Shield aggregation receipt evidence |
| AdamantineOS | Final verifier / policy boundary | Final execution decision after all required evidence is verified |

A key valid in one row is not valid in another row.

A signature valid in one domain is not valid in another domain.

A field name match is not authority.

A matching public algorithm identifier is not authority.

## Canonicalization Boundary

Q-ID canonicalization profiles are Q-ID contracts.

Shield v4 canonicalization is expected to use its own frozen profile:

- `shield-v4-canon.v1`

Q-ID canonical bytes must not be silently accepted as Shield v4 canonical bytes.

Shield v4 Known-Answer Test vectors must define Shield v4 canonical bytes independently.

Any future bridge must name the canonicalization profile explicitly and fail closed on mismatch.

## Domain Separation Boundary

Q-ID signatures and Shield v4 signatures must use separate domain separation.

A Q-ID login, authentication, binding, or identity-attestation signature must never verify as:

- a Shield component verdict signature
- a Shield Orchestrator receipt signature
- an AdamantineOS final approval

Shield v4 planned domain tags are Shield-owned, not Q-ID-owned:

- `DGB-SHIELD-V4-COMPONENT-VERDICT:<schema_version>:<policy_version>`
- `DGB-SHIELD-V4-ORCH-RECEIPT:<schema_version>:<policy_version>`

## Hybrid Semantics

Q-ID's hybrid model uses strict AND semantics.

Shield v4 may align with the same philosophy:

- all verifier-required algorithms must pass
- no optional path may override a required-path failure
- no first-valid-signature-wins behavior
- duplicate algorithm entries must fail closed
- unknown or unsupported algorithms must fail closed

For Shield v4, the verifier-required policy is authoritative.

Any embedded policy is signed evidence only and must not weaken the verifier's required policy.

## Q-ID Must Not Become Shield Authority

Q-ID must not expose or document any path where:

- Q-ID verifies Shield v4 final authority
- Q-ID grants Shield v4 execution approval
- Q-ID identity proof replaces Shield component signatures
- Q-ID identity proof replaces Shield Orchestrator signatures
- Q-ID keys are listed as Shield trust-registry keys
- Q-ID metadata upgrades a Shield `DENY` to `ALLOW`
- Q-ID output bypasses AdamantineOS final policy

If a future integration needs to pass Q-ID evidence into AdamantineOS, that evidence remains Q-ID evidence only.

## Future Integration Rule

A future Shield v4 integration may reference Q-ID for:

- algorithm naming consistency
- fail-closed philosophy
- no silent fallback philosophy
- hybrid strict AND semantics
- lessons learned from canonicalization and PQC backend selection

A future Shield v4 integration must not import from Q-ID:

- key authority
- trust registry authority
- final policy authority
- transaction authority
- wallet execution authority
- Shield component role authority
- Shield Orchestrator role authority

## Fail-Closed Requirements

Any future Q-ID / Shield bridge must fail closed if it sees:

- a Q-ID key used for a Shield role
- a Shield key used for a Q-ID role
- a Q-ID signature presented as a Shield signature
- a Shield signature presented as a Q-ID signature
- mismatched canonicalization profile
- missing Shield domain tag where Shield verification is required
- legacy algorithm labels without explicit compatibility rules
- weaker embedded policy than verifier-required policy
- missing required hybrid algorithm path
- optional FN-DSA/Falcon success while a required path fails

## V4.2 Exit Criteria

This Q-ID-side alignment is complete only when:

- Shield v4 can reuse naming philosophy without reusing Q-ID keys.
- Q-ID identity/authentication authority remains separate from Shield decision authority.
- ML-DSA and FN-DSA/Falcon wording is accurate.
- Hybrid semantics remain strict AND.
- No Q-ID document or implementation claims Shield final execution authority.
- No crypto implementation is added by this V4.2 step.
