# QID Reason Codes V1

## Frozen Enum Contract

This document defines the stable reason code enumeration for
QID_IDENTITY_ATTESTATION_V1.

These values are unsigned integers and MUST remain stable for V1. They
are shared across verification boundaries (e.g., Adamantine).

------------------------------------------------------------------------

# Enum Table

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

------------------------------------------------------------------------

# Rules

-   Reason codes MUST NOT change meaning within V1.
-   New codes require V2.
-   Implementations MUST return only defined codes.
-   No string-based reason identifiers allowed in verification core.
