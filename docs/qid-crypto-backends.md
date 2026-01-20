<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# DigiByte Q-ID — Crypto Backends (Non-Normative)

> **Status:** Developer documentation  
> **Normative rules live in `docs/CONTRACTS/`.**  
> If this document conflicts with a contract, **the contract wins**.

This document explains how cryptographic backends are selected in Q-ID and how
**CI-safe stub mode** differs from the **optional real PQC backend**.

---

## 1. Backend selection

Q-ID supports explicit backend selection via environment variable:

```text
QID_PQC_BACKEND
```

Valid values:
- *(unset)* — CI-safe stub backend (**default**)
- `liboqs` — real post-quantum backend (optional)

Any other value is invalid and results in an error.

Backend selection is resolved at runtime by `qid.pqc_backends.selected_backend()`.

---

## 2. CI-safe stub backend (default)

When `QID_PQC_BACKEND` is **not set**:

- Deterministic keys are generated
- Deterministic signatures are produced
- No external PQC libraries are required
- All algorithms remain selectable

This mode exists to ensure:
- portable CI
- deterministic testing
- reproducible examples

**Important:**  
Stub mode is *not* post-quantum secure. It is a **testing and development mode only**.

---

## 3. Real PQC backend (`liboqs`) — optional

When:

```bash
export QID_PQC_BACKEND=liboqs
```

Q-ID switches to **real cryptographic enforcement**:

- Algorithms `pqc-ml-dsa`, `pqc-falcon`, and `pqc-hybrid-ml-dsa-falcon` are enforced
- Silent fallback is explicitly forbidden
- Missing or invalid backend configuration raises `PQCBackendError`

Tests that require `liboqs` are **optional** and skipped automatically if unavailable.

---

## 4. Algorithm enforcement rules

### 4.1 Single-algorithm PQC

For:
- `pqc-ml-dsa`
- `pqc-falcon`

With real backend selected:
- Real PQC signatures are generated via `liboqs`
- Verification uses the same backend
- Any mismatch or error ⇒ verification fails

---

### 4.2 Hybrid algorithm (`pqc-hybrid-ml-dsa-falcon`)

Hybrid mode has **strict additional rules**.

When `QID_PQC_BACKEND=liboqs`:
- Both ML-DSA and Falcon signatures are required
- A **Hybrid Key Container v1** must be supplied
- The container binds both public keys deterministically
- Missing container ⇒ signing fails immediately

When stub mode is active:
- Hybrid signatures are simulated deterministically
- No container is required
- Behavior remains CI-safe

This distinction is **intentional and contract-aligned**.

---

## 5. No silent fallback guarantee

Q-ID enforces a **no silent fallback** rule:

- If a real backend is selected, stub behavior is forbidden
- If the backend is misconfigured, errors are explicit
- Callers may catch errors and fail-closed, but must not ignore them

This prevents accidental downgrade from PQC to non-PQC behavior.

---

## 6. Error handling expectations

Lower-level crypto functions may raise:
- `ValueError`
- `TypeError`
- `PQCBackendError`

Higher-level protocol helpers:
- may catch **expected** errors
- must fail-closed (e.g. return unverifiable messages)
- must not convert errors into success

---

## 7. Relationship to contracts

This document explains *how* backends are selected.

The following documents define *what must be signed and verified*:
- `docs/CONTRACTS/crypto_envelope_v1.md`
- `docs/CONTRACTS/hybrid_key_container_v1.md`

Always consult contracts before modifying backend behavior.

---

## License

MIT — Copyright (c) 2025 **DarekDGB**
