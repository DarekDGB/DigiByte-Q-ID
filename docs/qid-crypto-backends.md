# DigiByte Q-ID — Crypto Backends

Status: **draft – dev backend implemented, PQC backends TODO**

Q-ID is designed so that **cryptography is pluggable**. The public
`qid.crypto` API stays stable while different signing schemes can be
implemented behind it.

This document explains:

1. The current **dev backend** (HMAC-based).
2. How future **post-quantum (PQC) backends** (ML-DSA, Falcon, hybrid)
   can slot in.
3. How **Adamantine Wallet / Guardian / Shield** are expected to wire up
   Q-ID keys and policies.

---

## 1. Design goals

Q-ID crypto backends should:

- Keep the **public API stable** for application code:
  - `QIDKeyPair`
  - `generate_dev_keypair()` (and future key generators)
  - `sign_payload(...)`
  - `verify_payload(...)`
- Allow **multiple algorithms** to coexist (dev, PQC, hybrid).
- Be **testable** on simple environments (like GitHub Actions, iPhone,
  small devices).
- Integrate cleanly with:
  - **Adamantine Wallet** (wallet-side keys and signatures),
  - **Guardian / Shield** (policy and anomaly detection),
  - future **server-side identity services**.

Backends can differ internally, but they must all respect the same
semantic contract:

> Signing a given canonical JSON payload must always produce signatures
> that verify under the corresponding public key / configuration.

---

## 2. Current dev backend (HMAC-SHA256)

The first backend is intentionally simple and dependency-free.  
It lives in `qid/crypto.py` and is used only for **development and tests**.

### 2.1. Key representation

The dev backend uses a symmetric secret key, wrapped as `QIDKeyPair`:

```python
class QIDKeyPair:
    id: str
    public_key: str
    secret_key: bytes
```

- `id` — human-readable identifier, e.g. `"dev-hmac-primary"`.
- `public_key` — non-secret identifier used in payloads and logs.
- `secret_key` — random bytes used by HMAC-SHA256.

The helper `generate_dev_keypair()` creates a fresh keypair with random
secret bytes and a derived `id` / `public_key` string.

### 2.2. Payload signing

The dev backend signs **canonical JSON**:

```python
def sign_payload(payload: dict, keypair: QIDKeyPair) -> str:
    ...
```

Steps:

1. Serialize `payload` using `json.dumps(..., sort_keys=True,
   separators=(",", ":"))`.
2. Compute `HMAC-SHA256(secret_key, json_bytes)`.
3. Encode the MAC as URL-safe base64 without padding.
4. Return the encoded signature string.

### 2.3. Payload verification

Verification recomputes the MAC and compares:

```python
def verify_payload(payload: dict, signature: str, keypair: QIDKeyPair) -> bool:
    ...
```

1. Serialize `payload` in the same canonical way.
2. Decode the signature from base64url.
3. Recompute `HMAC-SHA256(secret_key, json_bytes)`.
4. Compare in constant time.
5. Return `True` only if they match.

### 2.4. Where it is used today

The dev backend is already wired into:

- `qid.crypto`:
  - `QIDKeyPair`
  - `generate_dev_keypair`
  - `sign_payload`
  - `verify_payload`
- `qid.protocol`:
  - `sign_login_response(...)`
  - `verify_login_response(...)`
  - `server_verify_login_response(...)`
- Tests:
  - `tests/test_crypto.py`
  - `tests/test_protocol_signing.py`

This makes the **signed login flow** fully functional for demos and
local testing, without requiring any external libraries.

> **Important:** The dev backend is **not meant for production**.  
> Wallets and servers should move to PQC or hybrid backends before any
> real-world deployment.

---

## 3. Future PQC backends (ML-DSA, Falcon, hybrid)

The long-term plan is to add **post-quantum** signing schemes beneath
the same API.

Potential candidates:

- **ML-DSA** (based on Dilithium, NIST standardization track).
- **Falcon**-style lattice signatures.
- A **hybrid** approach:
  - classical ECDSA + PQC signature together
  - OR dev-HMAC + PQC during migration phases.

### 3.1. Backend selection strategy

Q-ID should support a simple configuration mechanism (env var / config
file / wallet setting) to choose the active backend, for example:

- `"dev-hmac"` — current default for tests.
- `"ml-dsa"` — PQC-only.
- `"falcon"` — alternative PQC.
- `"hybrid-ecdsa-ml-dsa"` — dual-signature model.

The **public API does not change** – only the internal implementation of
`QIDKeyPair`, `sign_payload` and `verify_payload`.

Example idea (future work):

```python
def generate_keypair(backend: str = "dev-hmac") -> QIDKeyPair: ...
def sign_payload_with_backend(payload: dict, keypair: QIDKeyPair, backend: str) -> str: ...
```

For now, only `generate_dev_keypair()` is implemented, keeping the
surface area small and focused.

### 3.2. Storage & rotation considerations

When PQC backends are added, Q-ID should support:

- **Key rotation** with `key_id` fields in payloads.
- Multiple active keys per identity (e.g. old + new PQC key).
- Migration from dev keys → PQC keys without breaking logins.

The existing `build_login_response_payload(...)` already supports an
optional `key_id`, which prepares the protocol for this future.

---

## 4. Integration with Adamantine / Guardian / Shield

Q-ID is not a standalone wallet; it is designed to be embedded into the
**DigiByte Adamantine Wallet** and observed/guarded by:

- **Guardian Wallet / Guardian engine**
- **Quantum Wallet Guard (QWG)**
- **Sentinel AI / DQSN / ADN / Adaptive Core**

### 4.1. Wallet-side (Adamantine)

Adamantine is expected to:

- Hold one or more **Q-ID keypairs** in its secure storage.
- Use `qid.protocol.build_login_response_payload(...)` to shape the
  response.
- Use `qid.crypto.sign_payload(...)` (or a PQC backend) to sign.
- Attach:
  - `address`
  - `pubkey`
  - (optionally) `key_id`
- Display clear UX to the user:
  - which service they’re logging into,
  - which key / address is used,
  - what policies apply.

### 4.2. Node / policy side (Guardian, Shield stack)

Guardian / Shield-related components can use Q-ID signals for:

- **Policy decisions** (e.g. block logins from suspicious devices).
- **Anomaly detection** (strange login patterns, impossible travel,
  repeated failed verifications).
- **Audit trails** (signed login events correlated with on-chain
  activity).

Possible integration points:

- Guardian could maintain a **Q-ID credential registry** (service_id,
  key_id, allowed devices).
- Sentinel / DQSN could monitor:
  - abnormal Q-ID usage volume,
  - correlations with on-chain transactions,
  - suspected key abuse.

### 4.3. Server-side services

Service operators (exchanges, apps, websites) can:

- Use `server_verify_login_response(...)` as a **reference flow**.
- Replace the dev backend with their chosen PQC library.
- Optionally, register Q-ID credentials with Guardian / Shield for extra
  protection.

---

## 5. Roadmap / TODOs

Short-term:

- [ ] Add a **backend registry** in `qid.crypto` with a simple switch.
- [ ] Define a stable `generate_keypair(backend=...)` API.
- [ ] Document concrete PQC libraries to evaluate (depending on DigiByte
      core / community preferences).
- [ ] Tighten tests around canonicalization and signature misuse.

Medium-term:

- [ ] Implement at least one **PQC backend** (ML-DSA or Falcon-like).
- [ ] Implement a **hybrid backend** for migration phases.
- [ ] Extend threat model (`docs/qid-threat-model.md`) with PQC-specific
      considerations.

Long-term:

- [ ] Wire Q-ID crypto configuration into **Adamantine** builds.
- [ ] Expose Q-ID policy hooks to **Guardian / Shield**.
- [ ] Provide reference server implementations (Python / Go / Rust) that
      verify Q-ID signatures using production PQC libraries.

---

*This document describes how Q-ID keeps cryptography modular and ready
for a post-quantum future, while remaining lightweight enough to run in
simple environments (like your iPhone-only development workflow).*
