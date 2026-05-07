# Changelog

All notable changes to Q-ID will be documented in this file.

This project adheres to semantic versioning.

------------------------------------------------------------------------

## [1.1.0] - 2026-05-07

### Added

- Guardian Wallet v3 auth request contract (`contracts/guardian_qid_auth_request_v1.json`)
- Guardian Wallet v3 auth bridge module (`qid/integration/guardian_v3.py`)
- strict schema-level validator for Guardian Wallet v3 auth requests
- deterministic auth-request ID derivation for the Guardian Wallet v3 bridge
- fail-closed regression tests for auth bridge request construction and validation
- Guardian Wallet v3 auth bridge documentation
- Q-ID auth bridge release plan
- example roundtrip for Q-ID → Guardian Wallet v3 auth request building

### Changed

- aligned repository release surfaces to `v1.1.0`
- preserved existing legacy Guardian event adapter while adding explicit Guardian Wallet v3 auth support
- preserved Adamantine integration unchanged

### Security

- rejected unknown auth bridge signal keys fail-closed
- rejected malformed optional auth fields fail-closed
- enforced deterministic request shape for Guardian Wallet v3 auth mode
- preserved strict responsibility boundary: Q-ID verifies facts, Guardian evaluates policy

No breaking protocol changes.  
No authority expansion.

------------------------------------------------------------------------

## [1.0.2] - 2026-04-15

### Added

- Verification contract documentation (`docs/CONTRACTS/CONTRACT_QID_VERIFICATION.md`)
- Verification contract invariant tests covering accepted signature shapes and hybrid strict-AND behavior
- Explicit fail-closed tests for liboqs-only key generation requests

### Changed

- Aligned repository version truth to `v1.0.2` across package metadata and release surfaces
- Removed placeholder package-surface language from `qid/__init__.py`
- Stub verification now derives verification material from public material only

### Security

- Eliminated CI stub verification dependence on secret material
- Explicit liboqs key-generation requests now fail closed instead of silently downgrading
- Verification contract and backend fail-closed behavior are CI locked

No API surface changes.  
No protocol behavior changes.

------------------------------------------------------------------------

## [1.0.1] - 2026-03-XX

### Added

- Canonical JSON single-source helper (`qid.canonical.canonical_json_bytes`)
- Deterministic serialization regression tests
- Full canonicalization lock across:
  - crypto
  - pqc_sign
  - pqc_verify
  - binding
  - hybrid_key_container

### Changed

- Unified all security-critical serialization paths to a single canonical helper
- Removed per-module JSON serialization drift
- CI coverage enforcement increased to **100%**
- README and documentation aligned with real CI guarantees

### Security

- Eliminated serializer inconsistency risk across sign/verify paths
- Locked byte-level determinism for:
  - signatures
  - binding IDs
  - container hashes
- Strengthened fail-closed guarantees through deterministic serialization
- Added regression tests preventing future canonicalization drift

No API surface changes.  
No protocol behavior changes.

------------------------------------------------------------------------

## [1.0.0] - 2026-01-XX

### Added

- Adamantine integration adapter (evidence builder + verifier)
- Guardian integration adapter (policy event builder + verifier)
- Integration documentation for Adamantine and Guardian
- Stable release documentation (`docs/RELEASES/v1.0.0.md`)

### Changed

- Formalized transition from CI-locked pre-release phase to stable contract release
- Documentation aligned with stable integration surface

### Security

- Fail-closed validation model locked
- PQC backend enforcement remains strict (no silent fallback)
- Hybrid ML-DSA + Falcon container support fully retained
- Optional liboqs backend remains supported and CI-verified

No API surface changes relative to v0.1.2-ci-locked.  
No protocol behavior changes.
