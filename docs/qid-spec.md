<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# DigiByte Q-ID — Protocol Overview (Non‑Normative)

> **Status:** Developer documentation  
> **Normative truth lives in `docs/CONTRACTS/`.**  
> If this document conflicts with a contract, **the contract wins**.

This document explains how Q-ID fits together at a high level and how to read the contracts.
It does **not** define consensus or verification rules.

---

## 1. What Q-ID is

**Q-ID** is a cryptographically signed authentication and registration protocol for DigiByte,
designed as a long‑term successor to Digi‑ID with **post‑quantum readiness**.

It provides:
- Signed **login** flows
- Signed **registration** flows
- A `qid://` URI scheme (QR-first UX)
- Deterministic, CI‑safe behavior by default
- Optional real PQC enforcement via `liboqs`

---

## 2. Contract‑first architecture

Q-ID is intentionally **contract‑led**.

- All serialization, canonicalization, and verification rules are defined in **contracts**
- Code is a **reference implementation**
- Tests enforce that code follows contracts

### Normative contracts
See `docs/CONTRACTS/INDEX.md` for the authoritative list, including:
- Crypto Envelope v1
- Q-ID URI Scheme v1
- Login Payloads v1
- Registration Payloads v1
- Hybrid Key Container v1

---

## 3. Stub mode vs real PQC backend

Q-ID runs in **two explicit modes**.

### 3.1 CI‑safe stub mode (default)

When `QID_PQC_BACKEND` is **not set**:
- Deterministic keys and signatures are used
- No external PQC toolchain is required
- Suitable for CI, tests, examples, and documentation

This mode exists to keep the repo portable and reviewable.

### 3.2 Real PQC backend (optional)

When:
```
QID_PQC_BACKEND=liboqs
```

- PQC algorithms are enforced
- No silent fallback is allowed
- Missing backend or invalid configuration results in explicit errors

This mode is **optional** and intentionally gated.

---

## 4. Cryptography model (stub + real backend)

### Algorithms

Algorithm identifiers are defined in code and referenced by contracts:

- `dev-hmac-sha256`
- `pqc-ml-dsa`
- `pqc-falcon`
- `pqc-hybrid-ml-dsa-falcon`

Legacy alias:
- `hybrid-dev-ml-dsa` (accepted for compatibility only)

### Hybrid rule

When using `pqc-hybrid-ml-dsa-falcon` **with a real backend selected**:
- Both ML‑DSA and Falcon signatures are required
- A **Hybrid Key Container v1** must be provided
- Missing container ⇒ signing fails (fail‑closed)

---

## 5. Fail‑closed philosophy

Q-ID follows strict security rules:

- Invalid input ⇒ verification returns **False**
- Missing required data ⇒ signing fails
- No implicit downgrade between algorithms
- No hidden authority or automatic recovery

Protocol helpers are allowed to:
- catch expected configuration errors
- return values that **fail verification**

They must **not** silently succeed.

---

## 6. Reading the repo

Suggested order:
1. `docs/CONTRACTS/INDEX.md`
2. Individual contract documents
3. `qid/crypto.py`
4. `qid/protocol.py`
5. `examples/`

---

## 7. What this document is not

This document does **not**:
- Define consensus rules
- Replace contracts
- Promise production readiness

It exists to reduce confusion and guide reviewers.

---

## License

MIT — Copyright (c) 2025 **DarekDGB**
