# DigiByte Q-ID — Crypto Backends

Status: **draft – dev backend + PQC stubs implemented**

This document explains how the Q-ID reference implementation handles
cryptography today, and how it is designed to evolve once DigiByte Core
chooses an official post‑quantum (PQC) standard.

The goal is:

- keep the **Python reference code simple and portable**
- expose **stable interfaces** so real PQC libraries can drop in later
- make it clear which pieces are **development stubs** vs **production
  critical** code

---

## 1. Backends overview

All Q-ID crypto lives in `qid/crypto.py` and is exposed through:

- `QIDKeyPair` – minimal key pair structure
- `generate_keypair(algorithm: str)` – generic key generation
- `generate_dev_keypair()` – convenience for the default dev backend
- `sign_payload(payload, keypair)` – canonical JSON signing
- `verify_payload(payload, signature, keypair)` – signature verification

The following algorithm identifiers are currently defined:

```python
DEV_ALGO    = "dev-hmac-sha256"
ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "hybrid-dev-ml-dsa"
```

These strings are the **public contract** – they are what wallets,
servers and future bindings will negotiate on.

---

## 2. Dev backend – `dev-hmac-sha256` (current default)

**Purpose:** make Q-ID easy to prototype and test without requiring any
external crypto libraries.

Implementation details:

- 32‑byte random secret key
- public key = `sha256(secret_key)`
- signatures = `HMAC-SHA256(secret_key, canonical_json(payload))`
- encoded as base64 strings

Security notes:

- This behaves like a shared‑secret MAC, not a real public‑key scheme.
- It is **not intended for production** on the open internet.
- It is perfect for:
  - unit tests
  - local demos
  - offline experimentation
  - CI pipelines (GitHub Actions, etc.)

---

## 3. PQC stubs – `pqc-ml-dsa` and `pqc-falcon`

These backends model what a real PQC integration will look like while
remaining extremely small and dependency‑free.

Implementation (reference version):

- 64‑byte random secret key (to mimic larger PQC keys)
- public key = `sha256(secret_key)` (placeholder)
- signatures:
  - use `HMAC-SHA512(secret_key, canonical_json(payload))`
  - prefixed with the algorithm name:  
    `b"pqc-ml-dsa:" + mac` or `b"pqc-falcon:" + mac`
  - whole blob then base64‑encoded

Why this design is useful:

- Signatures from different backends are **not interchangeable** because
  of the explicit prefix.
- Switching to a real ML‑DSA or Falcon implementation later can reuse:
  - `QIDKeyPair`
  - `generate_keypair(algorithm)`
  - `sign_payload` / `verify_payload`
- All integration tests already exercise these code paths, so when real
  libraries are introduced we immediately know if anything breaks.

Production expectation:

- Replace the HMAC‑based stubs with:
  - real ML‑DSA key generation & signatures
  - real Falcon key generation & signatures
- Keep algorithm identifiers and function signatures exactly the same.

---

## 4. Hybrid backend – `hybrid-dev-ml-dsa`

Some deployments may want a **hybrid** strategy – combining a classical
algorithm with a PQC scheme during the migration period.

In the reference implementation this is simulated as:

- 64‑byte secret key, split into two 32‑byte halves: `s1` and `s2`
- signature parts:
  - `sig1 = HMAC-SHA256(s1, canonical_json(payload))`
  - `sig2 = HMAC-SHA512(s2, canonical_json(payload))`
- combined signature = `sig1 || sig2` (concatenated bytes, then base64)

Verification recomputes both parts and compares against the combined
signature.

Production expectation:

- Replace `sig1` with a classical scheme (e.g. ECDSA) or keep HMAC in
  closed / trusted environments.
- Replace `sig2` with a real PQC signature (e.g. ML‑DSA).
- Maintain the “two‑part signature” pattern so verifiers can require:
  - *both* parts valid (strict hybrid), or
  - *at least one* part valid (migration mode).

---

## 5. Migration strategy

Because all backends share the same interface, migration can happen in
layers:

1. **Prototype phase (today)**  
   - wallets and servers use `DEV_ALGO` or the PQC stub algorithms
   - focus on UX, QR formats, API flows and integration with Adamantine

2. **PQC adoption phase**  
   - plug in real ML‑DSA / Falcon implementations behind the same
     functions
   - keep algorithm identifiers stable

3. **Hybrid / hardening phase**  
   - introduce stricter validation rules
   - allow policies such as:
     - “only accept `HYBRID_ALGO` after block height X”
     - “reject `DEV_ALGO` for internet‑facing services”

---

## 6. What is *not* frozen yet

The following pieces are intentionally flexible and MAY change when
real PQC libraries are wired in:

- exact key sizes
- internal key and signature encoding formats
- how public keys map to on‑chain identities or DigiByte addresses

The following ARE treated as stable contracts:

- algorithm identifiers (`DEV_ALGO`, `ML_DSA_ALGO`, `FALCON_ALGO`,
  `HYBRID_ALGO`)
- function signatures and their high‑level behaviour
- the expectation that signatures are base64‑encoded opaque strings

---

## 7. Summary

- **Today:** everything runs on pure‑Python HMAC so Q-ID is easy to build,
  test and demo anywhere.
- **Tomorrow:** DigiByte Core can swap in real PQC and hybrid schemes
  without breaking wallets or servers that implement the current API.
- This document serves as the bridge between the **reference
  implementation** and a future **production‑grade** Q-ID crypto stack.
