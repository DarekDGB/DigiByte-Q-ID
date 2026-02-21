# Changelog

All notable changes to Q-ID will be documented in this file.

This project adheres to semantic versioning.

------------------------------------------------------------------------

## \[1.0.0\] - 2026-01-XX

### Added

-   Adamantine integration adapter (evidence builder + verifier)
-   Guardian integration adapter (policy event builder + verifier)
-   Integration documentation for Adamantine and Guardian
-   Stable release documentation (`docs/RELEASES/v1.0.0.md`)

### Changed

-   Formalized transition from CI-locked pre-release phase to stable
    contract release
-   Documentation aligned with stable integration surface

### Security

-   Fail-closed validation model locked
-   PQC backend enforcement remains strict (no silent fallback)
-   Hybrid ML-DSA + Falcon container support fully retained
-   Optional liboqs backend remains supported and CI-verified

No API surface changes relative to v0.1.2-ci-locked. No protocol
behavior changes.

------------------------------------------------------------------------

## \[0.1.2-ci-locked\] - 2026-01-XX

### Changed

-   CI coverage gate adjusted to â¥90% to account for optional
    liboqs-only execution paths
-   Default CI reflects stub-only execution environment

### Security

-   Real PQC paths fully exercised in optional liboqs workflow
-   No protocol or API changes

------------------------------------------------------------------------

## \[0.1.1-ci-locked\] - 2026-01-XX

### Changed

-   Coverage gate raised and enforced at â¥95%
-   README aligned strictly with code and test contracts
-   liboqs key generation paths fully covered

### Security

-   PQC backend enforcement hardened (no silent fallback)
-   Hybrid ML-DSA + Falcon rules fully locked and tested

No API surface changes. No protocol behavior changes.

------------------------------------------------------------------------

## \[0.1.0-ci-locked\] - 2026-01-XX

### Added

-   API surface contract frozen at `contracts/api_surface_v0_1.json`
-   CI: pytest + coverage gate (â¥90%)
-   CI-safe stub crypto with fail-closed PQC backend selection
-   Hybrid ML-DSA + Falcon container support

Purpose: Establish deterministic contract baseline.

------------------------------------------------------------------------

© 2025 DarekDGB
MIT License
