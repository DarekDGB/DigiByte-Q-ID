<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# DigiByte Q-ID — Adamantine Wallet Integration (Non-Normative)

> **Status:** Developer guidance  
> **Normative rules live in `docs/CONTRACTS/`.**  
> If this document conflicts with a contract, **the contract wins**.

This document explains how **DigiByte Q-ID** integrates with **Adamantine Wallet OS**
from a *protocol consumer* perspective. It does **not** define wallet security,
key storage, or UI behavior.

---

## 1. Scope and intent

Adamantine Wallet OS acts as a **Q-ID client**:
- it parses `qid://` URIs
- it signs Q-ID payloads
- it returns signed responses to services

Q-ID deliberately does **not**:
- mandate wallet UX
- define key custody models
- assume hardware or software isolation
- replace wallet security architecture

Those decisions belong to Adamantine.

---

## 2. Login integration

### 2.1 Receive login request

The wallet:
1. scans or receives a `qid://login` URI
2. decodes the login request payload
3. validates basic structure (type, service_id, nonce)

Helpers:
- `decode_login_request_uri`

---

### 2.2 Build login response

The wallet:
1. constructs a login response payload
2. signs it with the selected keypair
3. returns the signed payload to the service

Helpers:
- `build_login_response_payload`
- `sign_message` (protocol helper)

Wallet responsibilities:
- select the correct keypair
- ensure user intent (outside Q-ID scope)
- supply hybrid container if required

---

## 3. Registration integration

Registration is a wallet-driven action.

The wallet:
1. constructs a registration payload
2. signs it
3. sends it to the service

Helpers:
- `build_registration_payload`
- `sign_message`

Q-ID does not dictate:
- how registration is triggered
- whether multiple keys are supported
- how revocation is handled

---

## 4. Cryptography modes

### Stub mode (default)

- deterministic signing
- no external PQC backend
- suitable for development and CI

### Real PQC backend (`liboqs`)

When `QID_PQC_BACKEND=liboqs`:
- PQC algorithms are enforced
- hybrid requires `hybrid_container_b64`
- no silent fallback is allowed

Wallets must:
- explicitly provide required containers
- surface configuration errors to the user

---

## 5. Hybrid container handling

For `pqc-hybrid-ml-dsa-falcon`:
- the wallet owns container creation
- the container binds ML-DSA + Falcon public keys
- the container is passed alongside signing

Contract:
- `docs/CONTRACTS/hybrid_key_container_v1.md`

---

## 6. Fail-closed behavior

Wallet integrations must treat:
- signing errors
- verification errors
- backend misconfiguration

as **hard failures**.

Wallets may:
- catch errors
- present user-facing messages
- retry only after explicit correction

Wallets must **not**:
- auto-downgrade algorithms
- retry with weaker crypto
- ignore missing containers


---

## 6A. AdamantineOS `qid_verifier` adapter

AdamantineOS does not hold Q-ID signing keys. It expects the runtime integrator to inject a verifier callable with this shape:

```python
Callable[[Mapping[str, Any]], None]
```

The callable MUST return only after the Q-ID evidence has been authenticated. It MUST raise on malformed, forged, tampered, or unverifiable evidence. A placeholder/no-op callable is not a verifier and must not be used in production.

Use the Q-ID helper:

```python
from qid.integration.adamantine import build_adamantineos_qid_verifier

qid_verifier = build_adamantineos_qid_verifier(
    service=service_config,
    keypair=server_or_expected_qid_keypair,
)
```

Then inject that callable into AdamantineOS `orchestrator_v2` / `RuntimeHostV2`.

Required tests for an integration:

- valid Q-ID evidence v2 is accepted by the verifier
- tampered signature is rejected
- tampered signed response payload is rejected
- AdamantineOS denies when the verifier raises

This proves the T-1 boundary end-to-end: Q-ID authenticity is checked before AdamantineOS parses Q-ID evidence as a trusted session.

## 6B. Shape-A evidence boundary


## 6B. Canonical JSON boundary profile

Q-ID uses the named `adamantine-qid-canonical-json-v1` profile for AdamantineOS proof hashes.

The profile is defined in `qid/canonical_profiles.py` and documented in `docs/CONTRACTS/CANONICAL_JSON_PROFILES.md`.

Locked settings:

- `sort_keys=True`
- `separators=(",", ":")`
- `ensure_ascii=True`
- `allow_nan=False`

This profile is intentionally separate from the internal `qid-canonical-json-v1` profile, which preserves non-ASCII characters as UTF-8 bytes.

Shape-A Adamantine session evidence is a legacy local-session shape. Its hash is integrity-only. It is not signature/authenticity proof.

Shape-A MUST NOT be accepted directly from untrusted transport, UI input, bridge payloads, or network-facing APIs. External Q-ID integrations should use Q-ID evidence v2 plus the real `qid_verifier` callable above.
---

## 7. What this document is not

This document does **not**:
- define Adamantine Wallet OS architecture
- describe secure key storage
- define Guardian / policy integration
- promise production readiness

It exists to clarify **integration boundaries**.

---

## License

MIT — Copyright (c) 2025 **DarekDGB**
