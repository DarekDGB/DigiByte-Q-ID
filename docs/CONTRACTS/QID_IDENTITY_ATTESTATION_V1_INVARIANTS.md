# QID_IDENTITY_ATTESTATION_V1 Invariants

## Deterministic & Fail-Closed Identity Primitive

This document defines the non-negotiable invariants for
QID_IDENTITY_ATTESTATION_V1.

------------------------------------------------------------------------

# Core Security Invariants

1.  Hybrid signatures are mandatory.
2.  No downgrade mode is permitted.
3.  Classical signature required.
4.  PQC signature required.
5.  Unknown algorithms MUST be rejected.
6.  Algorithm mismatch MUST be rejected.
7.  Unknown fields MUST be rejected.
8.  Missing fields MUST be rejected.
9.  Canonical CBOR encoding only.
10. Non-canonical encoding MUST be rejected.

------------------------------------------------------------------------

# Determinism Invariants

11. Same input bytes → same decision.
12. No network calls during verification.
13. No global mutable state.
14. No time-based logic.
15. No randomness.
16. No implicit defaults.
17. No silent fallback behavior.

------------------------------------------------------------------------

# Challenge Binding Invariant

18. Both signatures MUST verify over the exact challenge bytes.
19. Challenge MUST be non-empty.
20. Challenge verification MUST be deterministic.

------------------------------------------------------------------------

# Cross-Repo Compatibility Invariant

21. Reason codes MUST align with shared enum contract.
22. Verification result MUST be deterministic for execution boundaries.

------------------------------------------------------------------------

Breaking any invariant requires QID_IDENTITY_ATTESTATION_V2.
