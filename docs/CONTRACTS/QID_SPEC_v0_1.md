# DigiByte Q-ID — Specification v0.1

**Author:** DarekDGB  
**License:** MIT  
**Status:** Contract-locked (v0.1)

This document defines the **normative protocol specification** for DigiByte Q-ID v0.1.
Anything described here is considered **stable and relied upon by tests**.

---

## 1. Design Goals

- Digi-ID compatible by default (legacy mode)
- Optional **dual-proof** authentication:
  - ECDSA / legacy signature
  - PQC signature (ML-DSA, Falcon, or Hybrid)
- CI-safe by default (no PQC dependencies required)
- Fail-closed on all verification paths
- Domain-scoped identity bindings
- No hidden authority or implicit trust

---

## 2. Require Modes

| Mode | Meaning |
|-----|--------|
| `legacy` | Digi-ID compatible (default) |
| `dual-proof` | Requires valid binding + PQC verification |

Rules:
- Missing `require` field defaults to `legacy`
- Request and response `require` MUST match

---

## 3. Login Request Payload

```json
{
  "type": "login_request",
  "service_id": "example.com",
  "nonce": "random-string",
  "callback_url": "https://callback",
  "require": "legacy | dual-proof",
  "version": "1"
}
```

---

## 4. Login Response Payload

```json
{
  "type": "login_response",
  "service_id": "example.com",
  "nonce": "random-string",
  "address": "DGB_ADDRESS",
  "pubkey": "BASE64_PUBKEY",
  "require": "legacy | dual-proof",
  "version": "1",
  "key_id": "optional",
  "binding_id": "required if dual-proof"
}
```

---

## 5. Binding Envelope

Bindings link a wallet to a **domain** and PQC policy.

### Binding Payload
```json
{
  "version": "1",
  "type": "binding",
  "domain": "example.com",
  "address": "DGB_ADDRESS",
  "policy": "ml-dsa | falcon | hybrid",
  "pqc_pubkeys": {
    "ml_dsa": "base64url | null",
    "falcon": "base64url | null"
  },
  "created_at": 123456,
  "expires_at": null
}
```

### Binding Envelope
```json
{
  "binding_id": "hash",
  "payload": { ... },
  "sig": "signature"
}
```

Rules:
- `created_at` MUST NOT be in the future
- `expires_at` (if present) MUST be >= now
- Domain must match request `service_id`
- Binding signature must verify

---

## 6. PQC Algorithms

| Identifier | Meaning |
|----------|--------|
| `pqc-ml-dsa` | ML-DSA (Dilithium) |
| `pqc-falcon` | Falcon |
| `pqc-hybrid-ml-dsa-falcon` | Strict AND hybrid |

Hybrid rules:
- Both signatures must verify
- Both public keys must be present

---

## 7. Fail-Closed Rules

- Missing binding → FAIL
- Missing resolver → FAIL
- Missing PQC backend → FAIL
- Invalid timestamps → FAIL
- Any exception → FAIL

No silent fallback is allowed.

---

## 8. CI Safety

- PQC backends are **optional**
- Real PQC tests run only when `oqs` is installed
- Default CI remains green without PQC dependencies

---

## 9. Compatibility

- Fully compatible with Digi-ID in `legacy` mode
- Dual-proof is opt-in and forward-compatible
- No protocol breaking changes allowed in v0.1
