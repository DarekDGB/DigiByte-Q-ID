# TEST_MATRIX_V1 --- QID_IDENTITY_ATTESTATION_V1

## Negative-First Regression Lock Plan (Canonical CBOR, Hybrid Required)

This document defines the required test matrix for
QID_IDENTITY_ATTESTATION_V1. Each test is designed to lock invariants
and enforce fail-closed determinism.

All tests MUST assert the returned reason code (uint) on DENY. All tests
MUST be deterministic across repeated runs.

------------------------------------------------------------------------

# Legend

-   **ALLOW**: verification accepts evidence
-   **DENY(x)**: verification rejects evidence with reason code `x`
-   **Mutations**: single, explicit changes applied to a known-good
    attestation bytestring

------------------------------------------------------------------------

# 0. Golden Fixture Requirements

Create one **known-good** canonical CBOR attestation fixture:

-   version=1
-   algorithm_classical=1 (Ed25519)
-   algorithm_pqc=1 (ML-DSA-65)
-   challenge = non-empty bytes (e.g., 32 bytes)
-   valid classical signature over challenge
-   valid PQC signature over challenge
-   canonical CBOR encoding (sorted integer keys, definite lengths)

Fixture ID: `FIXTURE_VALID_V1`

------------------------------------------------------------------------

# 1. Encoding Attacks (Canonical CBOR)

  ------------------------------------------------------------------------
          Test ID Mutation / Scenario                             Expected
  --------------- -------------------------------------- -----------------
          ENC-001 Non-canonical CBOR encoding (same                DENY(1)
                  semantic object, non-canonical form)   

          ENC-002 Indefinite-length map                            DENY(1)

          ENC-003 Indefinite-length bytes in any field             DENY(1)

          ENC-004 Unsorted map keys                                DENY(1)

          ENC-005 Duplicate keys                                   DENY(1)

          ENC-006 Floating point value anywhere                    DENY(1)

          ENC-007 Null value anywhere                              DENY(1)
  ------------------------------------------------------------------------

------------------------------------------------------------------------

# 2. Field Set Violations (Exact Keys {1..8})

     Test ID Mutation / Scenario                          Expected
  ---------- ------------------------------------------ ----------
    FSET-001 Remove key 1 (version)                        DENY(2)
    FSET-002 Remove key 2 (classical pubkey)               DENY(2)
    FSET-003 Remove key 3 (pqc pubkey)                     DENY(2)
    FSET-004 Remove key 4 (classical alg)                  DENY(2)
    FSET-005 Remove key 5 (pqc alg)                        DENY(2)
    FSET-006 Remove key 6 (challenge)                      DENY(2)
    FSET-007 Remove key 7 (classical sig)                  DENY(2)
    FSET-008 Remove key 8 (pqc sig)                        DENY(2)
    FSET-009 Add extra key 9                               DENY(2)
    FSET-010 Replace an integer key with a string key      DENY(2)
    FSET-011 Use out-of-range key (e.g., 99)               DENY(2)

------------------------------------------------------------------------

# 3. Type Violations

  ------------------------------------------------------------------------
          Test ID Mutation / Scenario                             Expected
  --------------- -------------------------------------- -----------------
         TYPE-001 version is bytes (not uint)                   DENY(3) or
                                                                   DENY(2)

         TYPE-002 algorithm_classical is bytes (not             DENY(4) or
                  uint)                                            DENY(2)

         TYPE-003 algorithm_pqc is bytes (not uint)             DENY(4) or
                                                                   DENY(2)

         TYPE-004 identity_pubkey_classical is uint (not        DENY(9) or
                  bytes)                                           DENY(2)

         TYPE-005 identity_pubkey_pqc is uint (not              DENY(9) or
                  bytes)                                           DENY(2)

         TYPE-006 challenge is uint (not bytes)                   DENY(10)

         TYPE-007 signature_classical is uint (not              DENY(5) or
                  bytes)                                           DENY(9)

         TYPE-008 signature_pqc is uint (not bytes)             DENY(6) or
                                                                   DENY(9)
  ------------------------------------------------------------------------

NOTE: If implementation chooses a single strict mapping, update expected
codes to match exact contract behavior and keep stable.

------------------------------------------------------------------------

# 4. Version Attacks

    Test ID Mutation / Scenario                         Expected
  --------- ----------------------------------------- ----------
    VER-001 version = 0                                  DENY(3)
    VER-002 version = 2                                  DENY(3)
    VER-003 version = max uint (overflow attempt)        DENY(3)
    VER-004 version = 1 but encoded non-canonically      DENY(1)

------------------------------------------------------------------------

# 5. Algorithm Enforcement

  ------------------------------------------------------------------------
          Test ID Mutation / Scenario                             Expected
  --------------- -------------------------------------- -----------------
          ALG-001 classical alg = 0 (unknown)                      DENY(4)

          ALG-002 classical alg = 2 (reserved but                  DENY(4)
                  unsupported in V1)                     

          ALG-003 pqc alg = 0 (unknown)                            DENY(4)

          ALG-004 pqc alg = 2 (reserved but unsupported            DENY(4)
                  in V1)                                 

          ALG-005 declared alg=1 but verified using                DENY(8)
                  wrong algorithm path                   
  ------------------------------------------------------------------------

------------------------------------------------------------------------

# 6. Hybrid Enforcement (No Downgrade)

    Test ID Mutation / Scenario                           Expected
  --------- --------------------------------- --------------------
    HYB-001 signature_classical missing                    DENY(5)
    HYB-002 signature_pqc missing                          DENY(6)
    HYB-003 signature_classical empty bytes     DENY(5) or DENY(9)
    HYB-004 signature_pqc empty bytes           DENY(6) or DENY(9)
    HYB-005 classical pubkey empty bytes                   DENY(9)
    HYB-006 pqc pubkey empty bytes                         DENY(9)

------------------------------------------------------------------------

# 7. Signature Integrity (Tamper Tests)

All these tests start from `FIXTURE_VALID_V1`.

  ------------------------------------------------------------------------
          Test ID Mutation / Scenario                             Expected
  --------------- -------------------------------------- -----------------
          SIG-001 Flip 1 byte in signature_classical               DENY(7)

          SIG-002 Flip 1 byte in signature_pqc                     DENY(7)

          SIG-003 Flip 1 byte in challenge (signatures             DENY(7)
                  unchanged)                             

          SIG-004 Replace classical pubkey (signatures             DENY(7)
                  unchanged)                             

          SIG-005 Replace pqc pubkey (signatures                   DENY(7)
                  unchanged)                             

          SIG-006 Signatures computed over different               DENY(7)
                  challenge (swap in another challenge)  
  ------------------------------------------------------------------------

------------------------------------------------------------------------

# 8. Challenge Validation

  ------------------------------------------------------------------------
          Test ID Mutation / Scenario                             Expected
  --------------- -------------------------------------- -----------------
         CHAL-001 challenge empty bytes                           DENY(10)

         CHAL-002 challenge excessively large (optional        DENY(10) or
                  limit)                                           DENY(9)

         CHAL-003 challenge not bytes (type violation)            DENY(10)
  ------------------------------------------------------------------------

------------------------------------------------------------------------

# 9. Determinism Locks

  ------------------------------------------------------------------------
                 Test ID Scenario                                 Expected
  ---------------------- ------------------------ ------------------------
                 DET-001 Verify same bytes 100x     identical result every
                         in loop                                      time

                 DET-002 Verify fixture in                identical result
                         separate process run     

                 DET-003 Canonical re-encode then         identical result
                         verify                   

                 DET-004 DENY case returns same      identical reason code
                         reason code across runs  
  ------------------------------------------------------------------------

------------------------------------------------------------------------

# 10. Adamantine Integration Harness (Required)

These tests prove Q-ID evidence flows into Adamantine deterministically.

  ------------------------------------------------------------------------
                 Test ID Scenario                                 Expected
  ---------------------- ------------------------ ------------------------
                ADAM-001 Envelope includes valid            ALLOW + stable
                         Q-ID evidence                        context_hash

                ADAM-002 Envelope includes          DENY(7) or appropriate
                         tampered Q-ID evidence                     reason

                ADAM-003 Envelope includes                         DENY(6)
                         missing PQC signature    

                ADAM-004 Envelope includes                         DENY(1)
                         non-canonical CBOR       
                         evidence                 
  ------------------------------------------------------------------------

Exit criteria: - Tests are locked in CI. - Any future change that alters
reason codes or determinism must fail CI.

------------------------------------------------------------------------

# Exit Criteria (Matrix Completion)

This matrix is considered complete when:

-   All tests pass in CI.
-   All reason codes are stable and asserted.
-   Negative tests outnumber happy-path tests.
-   Adamantine integration tests are present and deterministic.
