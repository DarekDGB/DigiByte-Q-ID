# Q-ID → Guardian Integration Guide (v1.0.0)

This document defines how Q-ID integrates with a Guardian policy engine
using a deterministic, fail-closed event adapter.

Scope: v1.0.0 stable release\
Out of scope: `docs/PROPOSALS/*` (future work)

------------------------------------------------------------------------

## Overview

Q-ID produces cryptographically verified login artifacts:

-   `login_uri`
-   `response_payload`
-   `qid_signature` (optional, depending on flow)

The Guardian integration layer **does not perform cryptographic
decisions**.\
Instead, it converts verified Q-ID artifacts into a strict,
policy-consumable event structure.

This keeps concerns separated:

-   Q-ID = identity + signature validation
-   Guardian = policy enforcement + rules evaluation
-   AdamantineOS = execution boundary decision layer

------------------------------------------------------------------------

## Entry Points

Located in:

    qid/integration/guardian.py

Public functions:

-   `build_guardian_qid_login_event(...)`
-   `verify_guardian_qid_login_event(event)`

------------------------------------------------------------------------

## 1. Building a Guardian Login Event

### Function

``` python
build_guardian_qid_login_event(
    service: GuardianServiceConfig,
    login_uri: str,
    response_payload: dict,
    qid_signature: Optional[str] = None,
    include_login_uri: bool = True,
) -> dict
```

### Input Requirements (Fail-Closed)

The function will raise `TypeError` if:

-   `login_uri` is empty or not a string
-   `response_payload` is not a mapping
-   required fields are missing or invalid
-   `nonce` does not match the one embedded in `login_uri`
-   `service_id` mismatch
-   `callback_url` mismatch
-   optional fields are malformed (e.g. empty `key_id`)

### Required Response Fields

From `response_payload`:

-   `service_id`
-   `callback_url`
-   `nonce`
-   `address`
-   `pubkey`

Optional:

-   `key_id` (must be non-empty if present)

------------------------------------------------------------------------

## 2. Guardian Event Shape (v1.0.0)

Deterministic event output:

``` json
{
  "v": "1",
  "kind": "qid_login_event_v1",
  "service_id": "...",
  "callback_url": "...",
  "nonce": "...",
  "address": "...",
  "pubkey": "...",
  "key_id": "...",              // optional
  "qid_signature": "...",       // optional
  "login_uri": "..."            // optional (controlled by include_login_uri)
}
```

Design rules:

-   Strict schema
-   No unknown keys (deny-by-default)
-   No silent fallback
-   Versioned (`"v": "1"`)
-   Explicit event kind

------------------------------------------------------------------------

## 3. Verifying Guardian Event

### Function

``` python
verify_guardian_qid_login_event(event: Any) -> bool
```

Behavior:

-   Returns `False` for:
    -   wrong `v`
    -   wrong `kind`
    -   unexpected keys
    -   missing required keys
    -   empty required fields
    -   malformed optional fields
    -   non-mapping input
-   Never raises for invalid input
-   Always fail-closed

Guardian verification is **structural validation only**.\
Cryptographic validity must already be enforced by Q-ID before event
construction.

------------------------------------------------------------------------

## 4. Recommended Flow

1.  Wallet builds Q-ID login response
2.  Server verifies Q-ID signature
3.  Server builds Guardian event
4.  Guardian policy engine evaluates event
5.  Policy engine returns decision

------------------------------------------------------------------------

## 5. Security Model

Guardian adapter guarantees:

-   Deterministic event structure
-   Strict validation
-   No silent coercion
-   No implicit field defaults
-   Explicit versioning

It does NOT:

-   Verify PQC signatures
-   Make access decisions
-   Perform replay protection (handled upstream)

------------------------------------------------------------------------

## 6. Integration Boundaries

  Layer          Responsibility
  -------------- -----------------------------------
  Q-ID           Identity + PQC verification
  Guardian       Policy rules engine
  AdamantineOS   Execution boundary decision
  Orchestrator   Optional cross-layer coordination

------------------------------------------------------------------------

## 7. Stability Guarantee

For v1.0.0:

-   Event shape is considered stable.
-   Breaking schema changes require major version bump.
-   Future proposals live in `docs/PROPOSALS/` and are excluded from
    v1.0.0 contract guarantees.

------------------------------------------------------------------------

© 2026 DarekDGB\
MIT License
