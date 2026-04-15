<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# DigiByte Q-ID Test Tiers

## Purpose

This document defines the two test tiers that protect Q-ID from silent drift.

Q-ID uses a deterministic release gate and a separate real-backend proof gate.
They serve different purposes and must not be conflated.

---

## Tier 1 — Main deterministic baseline

Workflow:
- `.github/workflows/tests.yml`

Properties:
- runs on push and pull request
- installs `.[dev]`
- does not require `liboqs`
- runs the default deterministic suite
- enforces `--cov-fail-under=100`

Tier 1 is the primary release gate.
A release is not ready if Tier 1 is not green.

---

## Tier 2 — Optional real PQC backend proof

Workflow:
- `.github/workflows/pqc-optional-liboqs.yml`

Properties:
- runs on manual dispatch
- runs on schedule
- runs automatically for PQC-relevant changes
- enables:
  - `QID_PQC_BACKEND=liboqs`
  - `QID_PQC_TESTS=1`
- proves that real backend paths still work under explicit selection

Tier 2 is not a replacement for Tier 1.
It is additional backend proof.

---

## Required Interpretation

- Tier 1 defines the deterministic baseline
- Tier 2 proves optional real-backend compatibility
- both tiers must remain truthful
- neither tier may silently weaken fail-closed behavior

---

## Release Rule

Q-ID v1.0.2 may be treated as release-ready only when:
- Tier 1 is green
- Tier 1 coverage remains 100%
- contract tests are green
- Tier 2 remains green when invoked

---

## Final Principle

Q-ID does not guess which test tier matters.
It names them explicitly and keeps them separate.
