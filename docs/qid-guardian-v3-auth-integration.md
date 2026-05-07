# Q-ID → Guardian Wallet v3 Auth Integration

**Status:** Phase 2 documentation lock  
**Q-ID release target:** `v1.1.0`  
**Guardian Wallet release target:** `v3.0.0`

---

## Purpose

This document defines the **Q-ID → Guardian Wallet v3 auth bridge**.

It exists so that:

- Q-ID remains responsible for **identity verification**
- Guardian Wallet v3 remains responsible for **policy evaluation**
- auth flows are evaluated explicitly as **auth**, not faked as transaction requests

This integration is **deterministic**, **fail-closed**, and **contract-first**.

---

## Design Rule

**Q-ID auth must not be encoded as `tx_ctx`.**

Instead, Guardian Wallet v3 receives:

- `mode = "qid_auth"`
- empty `wallet_ctx`
- empty `tx_ctx`
- populated `auth_ctx`
- optional `extra_signals`

This preserves architectural clarity.

---

## Q-ID Public Bridge API

Located in:

`qid/integration/guardian_v3.py`

Public functions:

- `build_guardian_v3_qid_auth_request(...)`
- `verify_guardian_v3_qid_auth_request(...)`

---

## Contract File

The request contract lives at:

`contracts/guardian_qid_auth_request_v1.json`

This contract defines the request shape Q-ID builds for Guardian Wallet v3.

---

## Request Shape

Canonical request shape:

```json
{
  "contract_version": 3,
  "component": "guardian_wallet",
  "mode": "qid_auth",
  "request_id": "<deterministic-or-explicit-id>",
  "wallet_ctx": {},
  "tx_ctx": {},
  "auth_ctx": {
    "qid_verified": true,
    "binding_verified": true,
    "service_id": "example.com",
    "callback_url": "https://example.com/qid",
    "nonce": "abc123",
    "address": "DGB_ADDRESS",
    "pubkey": "PUBKEY",
    "key_id": "primary",
    "require": "legacy"
  },
  "extra_signals": {
    "trusted_device": true,
    "session": "session-1",
    "sentinel_status": "NORMAL"
  }
}
```

---

## `auth_ctx` Rules

Required fields:

- `qid_verified`
- `service_id`
- `callback_url`
- `nonce`
- `address`
- `pubkey`

Optional fields:

- `binding_verified`
- `key_id`
- `require`
- `issued_at`
- `expires_at`

Rules:

- `qid_verified` must be boolean
- `binding_verified` must be boolean when present
- `require` must be one of:
  - `legacy`
  - `dual-proof`
- `issued_at` and `expires_at` must appear together
- `expires_at` must be greater than `issued_at`

---

## `extra_signals` Rules

Allowed keys:

- `device_fingerprint`
- `sentinel_status`
- `geo_ip`
- `session`
- `trusted_device`
- `device_mismatch`

Rules:

- unknown keys are rejected
- `trusted_device` and `device_mismatch` must be boolean
- all other signal values must be non-empty strings

---

## Fail-Closed Behavior

Q-ID bridge construction fails closed when:

- `login_uri` is invalid
- `response_payload` is invalid
- expected `service_id` does not match
- expected `callback_url` does not match
- nonce mismatch occurs
- unknown signal keys are present
- malformed optional fields are present

Structural validation via `verify_guardian_v3_qid_auth_request(...)` returns `False` on invalid input and never permits unknown schema drift.

---

## Responsibility Split

| Layer | Responsibility |
|---|---|
| Q-ID | cryptographic verification, identity facts, binding facts |
| Guardian Wallet v3 | deterministic policy evaluation |
| AdamantineOS / orchestrator | final higher-level execution decisions |

---

## Recommended Flow

1. Wallet scans Q-ID login request
2. Wallet signs login response
3. Service verifies Q-ID response cryptographically
4. Service builds Guardian Wallet v3 auth request
5. Guardian Wallet v3 evaluates `mode="qid_auth"`
6. Upstream system treats:
   - `allow` as proceed
   - `escalate` as step-up
   - `deny` as block

---

## Minimal Example

```python
from qid.integration.guardian import GuardianServiceConfig
from qid.integration.guardian_v3 import (
    build_guardian_v3_qid_auth_request,
    verify_guardian_v3_qid_auth_request,
)

guardian_service = GuardianServiceConfig(
    service_id="example.com",
    callback_url="https://example.com/qid",
)

request = build_guardian_v3_qid_auth_request(
    service=guardian_service,
    login_uri=login_uri,
    response_payload=response_payload,
    qid_verified=True,
    binding_verified=True,
    extra_signals={
        "trusted_device": True,
        "session": "session-1",
        "sentinel_status": "NORMAL",
    },
)

if not verify_guardian_v3_qid_auth_request(request):
    raise RuntimeError("Invalid Guardian Wallet v3 auth request")
```

---

## Stability Statement

This bridge is additive.

It does **not** replace the existing Q-ID Guardian login event adapter at:

`qid/integration/guardian.py`

Both adapters may coexist:

- legacy policy event adapter
- Guardian Wallet v3 auth bridge

Breaking changes to this request contract require a new contract version.

---

**Author:** DarekDGB  
**License:** MIT
