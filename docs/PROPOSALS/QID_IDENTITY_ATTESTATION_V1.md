# QID_IDENTITY_ATTESTATION_V1

## Deterministic Hybrid Identity Attestation (Canonical CBOR)

------------------------------------------------------------------------

# 1. Status

This document defines the frozen contract for
QID_IDENTITY_ATTESTATION_V1.

This is a foundational identity primitive designed for deterministic,
fail-closed verification in AI-governed financial systems.

Schema version: 1\
Encoding: Canonical CBOR (RFC 8949 canonical form only)

------------------------------------------------------------------------

# 2. Encoding Rules (Mandatory)

The attestation object MUST:

-   Use canonical CBOR encoding (RFC 8949 canonical form)
-   Use definite-length encoding only
-   Use a CBOR map with integer keys
-   Include keys in sorted order
-   Contain exactly the defined key set (no more, no less)
-   Contain no null values
-   Contain no floating point values
-   Contain no indefinite-length items
-   Reject unknown keys

Violation of any encoding rule → DENY(1) NON_CANONICAL_ENCODING or
DENY(2) INVALID_FIELD_SET

------------------------------------------------------------------------

# 3. CBOR Map Structure

The CBOR map MUST contain exactly the following keys:

  Key   Field Name                  Type    Required
  ----- --------------------------- ------- ----------
  1     version                     uint    Yes
  2     identity_pubkey_classical   bytes   Yes
  3     identity_pubkey_pqc         bytes   Yes
  4     algorithm_classical         uint    Yes
  5     algorithm_pqc               uint    Yes
  6     challenge                   bytes   Yes
  7     signature_classical         bytes   Yes
  8     signature_pqc               bytes   Yes

Missing key → DENY(2) INVALID_FIELD_SET\
Extra key → DENY(2) INVALID_FIELD_SET

------------------------------------------------------------------------

# 4. Field Constraints

## 4.1 Version

-   Must equal 1
-   Any other value → DENY(3) VERSION_INVALID

## 4.2 Algorithm Enums

### Classical Algorithm Enum

  Value   Algorithm
  ------- ----------------------
  1       Ed25519
  2       secp256k1 (reserved)
  3       RSA-3072 (reserved)

V1 support: 1 only

### PQC Algorithm Enum

  Value   Algorithm
  ------- -----------------------
  1       ML-DSA-65
  2       ML-DSA-87 (reserved)
  3       Falcon-512 (reserved)

V1 support: 1 only

Unknown enum → DENY(4) ALGORITHM_UNSUPPORTED\
Mismatch between declared enum and verification method → DENY(8)
ALGORITHM_MISMATCH

------------------------------------------------------------------------

# 5. Signature Binding Model

Both signatures MUST verify over:

    challenge (exact byte sequence)

Signatures MUST NOT be computed over:

-   The full CBOR object
-   Identity fields
-   Any derived structure

This ensures identity neutrality and verifier-controlled binding.

Missing classical signature → DENY(5) CLASSICAL_REQUIRED\
Missing PQC signature → DENY(6) PQC_REQUIRED\
Invalid signature → DENY(7) SIGNATURE_INVALID

------------------------------------------------------------------------

# 6. Deterministic Verification Procedure

Verification MUST execute the following steps:

1.  Decode CBOR and validate canonical encoding.
2.  Validate exact key set {1..8}.
3.  Validate version == 1.
4.  Validate algorithm enums are supported.
5.  Validate challenge is non-empty.
6.  Verify classical signature over challenge.
7.  Verify PQC signature over challenge.
8.  If all checks pass → ALLOW.
9.  If any check fails → DENY(reason_code).

Verification MUST:

-   Make no network calls.
-   Use no global mutable state.
-   Use no time-based logic.
-   Use no randomness.
-   Produce deterministic output for identical input bytes.

------------------------------------------------------------------------

# 7. Reason Code Enum (Frozen)

  Code   Name
  ------ ------------------------
  1      NON_CANONICAL_ENCODING
  2      INVALID_FIELD_SET
  3      VERSION_INVALID
  4      ALGORITHM_UNSUPPORTED
  5      CLASSICAL_REQUIRED
  6      PQC_REQUIRED
  7      SIGNATURE_INVALID
  8      ALGORITHM_MISMATCH
  9      EMPTY_FIELD
  10     INVALID_CHALLENGE

Reason codes MUST remain stable for V1.

------------------------------------------------------------------------

# 8. Invariants

-   Hybrid signatures are mandatory.
-   No downgrade mode permitted.
-   Unknown algorithms rejected.
-   Unknown fields rejected.
-   Same input bytes → same decision.
-   Verification must be fail-closed.

------------------------------------------------------------------------

# 9. Cross-Repo Contract Guarantee

QID_IDENTITY_ATTESTATION_V1 is designed to be consumed by deterministic
execution boundaries (e.g., Adamantine).

Verification result MUST be deterministic and compatible with shared
reason code enums.

------------------------------------------------------------------------

# 10. Schema Freeze Declaration

QID_IDENTITY_ATTESTATION_V1 is considered frozen when:

-   This contract document is committed.
-   Test coverage validates all failure paths.
-   Integration test with execution boundary passes deterministically.

Future breaking changes require QID_IDENTITY_ATTESTATION_V2.
