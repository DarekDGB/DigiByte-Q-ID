<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# SECURITY POLICY

## DigiByte Q-ID — v1.0.1

---

## 🛡️ Security Philosophy

Q-ID is built on strict, non-negotiable principles:

- Fail-closed by default
- Deterministic behavior only
- No silent fallback
- Explicit cryptographic intent
- Test-locked guarantees

If something is uncertain → it must FAIL.

---

## 🔒 Core Security Guarantees

### 1. Fail-Closed Enforcement
All verification paths MUST:

- Reject invalid input
- Reject malformed payloads
- Reject missing fields
- Reject unexpected structures

No recovery paths.  
No soft failures.  
No partial success.

---

### 2. Deterministic Canonicalization

All security-critical serialization uses:

    qid.canonical.canonical_json_bytes

This ensures:

- identical signing and verification bytes
- no cross-module drift
- stable hashing and binding IDs

Any deviation is considered a security violation.

---

### 3. No Silent Fallback

If a cryptographic backend is required:

- It MUST exist
- It MUST be used
- If unavailable → FAIL

Never fallback silently to stub or alternative logic.

---

### 4. PQC Backend Rules

Default mode:
- Stub (CI-safe)

Optional real PQC:

    QID_PQC_BACKEND=liboqs
    QID_PQC_TESTS=1

Rules:
- Explicit opt-in only
- Backend must be present
- Missing backend → FAIL

---

### 5. Hybrid Signature Enforcement

Hybrid mode = strict AND

- ML-DSA must verify
- Falcon must verify
- Any failure → full rejection

No downgrade allowed.

---

### 6. Signature Integrity

- Payload must be signed exactly as verified
- No transformation allowed between sign and verify
- Canonical bytes must match exactly

---

## ⚠️ Threat Model

Q-ID is designed to resist:

- serialization inconsistencies
- replay attacks (nonce-based flows)
- signature tampering
- downgrade attacks
- partial verification bypass
- backend misconfiguration

---

## 🚫 Explicit Non-Goals

Q-ID does NOT:

- store private keys
- manage custody
- auto-select cryptographic backends
- perform implicit recovery

---

## 🧪 Security Validation

Security is enforced through:

- 100% test coverage (CI enforced)
- canonicalization regression tests
- fail-closed path testing
- hybrid verification tests
- PQC backend enforcement tests

---

## 📢 Reporting Vulnerabilities

If you discover a security issue, report it privately:

📧 adamantinewalletos@gmail.com

Please include:

- clear description
- reproduction steps
- impact assessment (if known)

---

## 📦 Version Scope

This policy applies to:

- Q-ID v1.0.1
- All subsequent hardening releases unless explicitly changed

---

## 🛡️ Final Principle

Q-ID does not guess.  
Q-ID does not fallback.  
Q-ID verifies.

---

© DarekDGB
