<!--
Author: DarekDGB
License: MIT (c) 2025
-->

# DigiByte Q-ID — CI & Contract Locking

**Author:** DarekDGB  
**License:** MIT (c) 2025

## Why we lock a contract

Q-ID is a security protocol. The most dangerous failures are small interface drift:
- parameters renamed
- argument order changed
- optional args added that alter behavior
- helpers promoted to public accidentally
- CI rules drifting away from the release baseline

To prevent this, Q-ID freezes an explicit **API surface contract** and a **test-tier contract**.

---

## API surface contract

The contract is stored at:

- `contracts/api_surface_v0_1.json`

It records:
- the public functions that are allowed
- the import path for each
- the positional arg names (order matters)
- the kwonly arg names (order matters)

CI enforces that the actual Python function signatures match the contract exactly.

This makes API drift **impossible to miss**.

---

## Test tiers

Q-ID uses two explicit test tiers.

### Tier 1 — Main deterministic baseline

This is the default release gate.

Properties:
- always runs on push and pull request
- installs `.[dev]`
- runs without requiring `liboqs`
- enforces `--cov-fail-under=100`
- proves the contract-locked baseline remains deterministic

This tier is the source of truth for everyday development.

### Tier 2 — Optional real PQC backend proof

This tier proves the real `liboqs` path.

Properties:
- runs on `workflow_dispatch`
- runs on schedule for drift detection
- runs automatically for PQC-relevant pushes and pull requests
- sets `QID_PQC_BACKEND=liboqs`
- sets `QID_PQC_TESTS=1`
- validates that explicit backend selection remains fail-closed

This tier is **additional proof**, not a substitute for Tier 1.

---

## CI: pytest + coverage gate

Tier 1 CI runs:
- `pytest`
- `pytest-cov`
- coverage gate `= 100%`

Why coverage is enforced:
- security code must be exercised
- fail-closed paths must be tested
- regression drift should be caught immediately
- release truth must match the repository baseline

---

## Why the PQC workflow is separate

Real PQC depends on optional tooling (`liboqs` / `oqs`).
Q-ID does **not** allow that dependency to weaken the deterministic release gate.

So Q-ID keeps:
- main CI: always runs, deterministic, coverage-locked
- optional PQC CI: proves the real backend path under explicit opt-in

This yields:
- reproducible baseline everywhere
- real-crypto proof when the environment supports it
- no ambiguity about which tier blocks a release

---

## Tags and releases

A release-ready state must keep all of the following aligned:
- repository version truth
- API surface contract
- Tier 1 deterministic gate
- Tier 2 optional real-backend proof

Recommendation:
- keep building on `main`
- cut a new tag only when tests, docs, and contracts all agree

---

## Definition of “contract-locked”

A state is considered contract-locked when:
- tests are green
- Tier 1 coverage gate passes at 100%
- `api_surface_v0_1.json` is valid JSON and enforced
- deterministic behavior is preserved
- no silent fallback exists for selected PQC backends
- Tier 2 continues to prove the real backend path when invoked
