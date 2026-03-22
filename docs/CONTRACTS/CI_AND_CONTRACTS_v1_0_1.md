# CI & CONTRACT GUARANTEES

## Q-ID v1.0.1 — Coverage Lock & Determinism

---

## 🔒 Core Invariants

The following properties are permanently enforced:

- Deterministic canonical JSON (single source: `canonical_json_bytes`)
- 100% test coverage (line + branch)
- Fail-closed verification
- No silent fallback
- Explicit PQC backend selection
- Hybrid verification = strict AND

---

## 🧪 Coverage Policy

- Minimum coverage: **100%**
- Enforced in CI pipeline
- Any drop → CI FAIL
- No exceptions
- No partial merges

---

## 🧬 Canonicalization Contract

All security-critical serialization MUST use:

    qid.canonical.canonical_json_bytes

Forbidden patterns:

    json.dumps(...).encode("utf-8")

---

## 🔐 Signing & Verification Contract

- Same canonical bytes MUST be used for:
  - signing
  - verification
- Any mismatch → FAIL

---

## ⚠️ Fail-Closed Rules

System must reject on:

- malformed payload
- invalid signature
- missing PQC fields
- backend misconfiguration
- unexpected structure

No fallback.
No silent behavior.

---

## 🧩 PQC Backend Rules

Default:
- Stub (CI-safe)

Optional:
    QID_PQC_BACKEND=liboqs
    QID_PQC_TESTS=1

Rules:
- If backend requested → MUST exist
- If missing → FAIL
- Never fallback silently

---

## 🧠 Hybrid Rules

Hybrid = ML-DSA AND Falcon

- both must verify
- one fail = full fail

---

## 📦 Version Truth

Current:
- Version: v1.0.1
- Coverage lock: active
- Canonicalization: locked

---

## 🛡️ Final Principle

Q-ID does not assume.
Q-ID does not fallback.
Q-ID does not guess.

Q-ID verifies.

---

© DarekDGB
