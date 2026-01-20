<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# 🔐 DigiByte Q-ID
## **Quantum-Ready Authentication Protocol with Hybrid Signatures, PQC Backends & Adamantine Integration**
### **Developer Preview v0.1 — Designed for Long-Term Survivability**

> **Q-ID operates fully standalone, and is designed to integrate with the Adamantine Wallet and the DigiByte Quantum Shield as future-compatible consumers of signed authentication events.**

---

Q-ID is a **next-generation authentication protocol** engineered as the evolutionary successor to Digi-ID.  
It is not a simple upgrade — it is a **complete redesign** around:

- **Cryptographically signed authentication flows**
- **PQC-ready signature backends (ML-DSA, Falcon)**
- **Hybrid (dual-signature) support**
- **Strict service binding & replay protection**
- **Modular architecture** for wallets and services
- **Adamantine-native integration helpers**
- **Future-compatible Guardian / Shield telemetry**
- **QR-first, passwordless login**
- **Full test coverage & CI validation**

This README is intentionally deep and technical — a full architectural brief for engineers reviewing the protocol.

Q-ID is built to withstand not only today’s threats…  
but also **the next cryptographic era**.

---

# ⭐️ 1. Why Q-ID Exists

Legacy Digi-ID is elegant — but limited:

- ❌ No signature on login responses
- ❌ No PQC migration path
- ❌ No hybrid cryptography
- ❌ No server-side verification standard
- ❌ No strict service binding
- ❌ No tamper detection
- ❌ No nonce replay protection rules

Q-ID fixes this by introducing a **fully signed, verifiable authentication model** with a flexible cryptographic backend designed for a world where **quantum computers are real adversaries**.

---

# ⭐️ 2. High-Level Architecture

```
┌─────────────────────────────────────────────┐
│                 Client Wallet               │
│                                             │
│  Scan QR → Decode URI → Validate Service →  │
│  Build Response → Sign Response → Send Back │
└─────────────────────────────────────────────┘
                    ▲              │
                    │              ▼
┌─────────────────────────────────────────────┐
│                Service Backend              │
│                                             │
│    Issue Login URI → Verify Signature →     │
│    Validate Nonce → Approve Session         │
└─────────────────────────────────────────────┘
```

Q-ID is composed of four coherent layers:

```
qid/
  crypto/           ← pluggable signature engines (DEV / PQC / HYBRID)
  protocol/         ← core login / registration flows
  integration/      ← Adamantine signing / verification helpers
  examples/         ← demos (server, roundtrip, mobile)
```

---

# ⭐️ 3. Cryptographic Layer (PQC-Ready Architecture)

Q-ID ships with a **pluggable crypto backend system**.  
Every keypair, signature, and verification step is bound to an explicit algorithm identifier.

| Algorithm Identifier            | Purpose                                  | Status |
|--------------------------------|------------------------------------------|--------|
| `dev-hmac-sha256`              | Development / CI / tests                 | ✔ Stable |
| `pqc-ml-dsa`                   | ML-DSA (Dilithium family)                | ✔ CI-safe stub / real via liboqs |
| `pqc-falcon`                   | Falcon family                            | ✔ CI-safe stub / real via liboqs |
| `pqc-hybrid-ml-dsa-falcon`     | Hybrid (ML-DSA + Falcon)                 | ✔ CI-safe stub / container-required via liboqs |

Legacy compatibility:
- `hybrid-dev-ml-dsa` is accepted as a **legacy alias only** (do not use for new integrations).

### Stub mode vs real PQC backend

- **Default (stub mode):**
  - Deterministic, CI-safe keys and signatures
  - No external PQC dependency
- **Real PQC mode:**
  - Enabled by `QID_PQC_BACKEND=liboqs`
  - Enforces real ML-DSA / Falcon signatures
  - **Hybrid requires an explicit Hybrid Key Container**
  - No silent fallback is allowed

---

# ⭐️ 4. Protocol Layer (Q-ID Core)

The Q-ID protocol supports:

### ✔ Login Requests (Service → Wallet)
- service ID
- nonce
- callback URL
- versioning
- algorithm awareness

### ✔ Login Responses (Wallet → Service)
- signed payload
- strict validation of:
  `service_id`, `callback_url`, `nonce`, `address`, `key_id`, `algorithm`

### ✔ Registration Payloads
- signed identity association
- deterministic canonical encoding

All payloads are **canonicalized**, **verified**, and **fail-closed**.

---

# ⭐️ 5. Adamantine Wallet Integration

Q-ID provides **first-class integration helpers** for Adamantine:

```
qid.integration.adamantine
```

These helpers:
- build signed wallet responses
- verify responses server-side
- enforce strict service and callback binding
- support DEV / PQC / HYBRID keypairs

Wallet security, UX, and key custody remain **explicitly out of scope** for Q-ID.

---

# ⭐️ 6. Server-Side Verification

Services verify login responses using strict rules:

- nonce must match
- service_id must match
- callback_url must match
- signature must verify
- algorithm downgrade is forbidden

Any mismatch ⇒ **authentication fails** (fail-closed).

Reference implementation:
```
examples/example_server.py
```

---

# ⭐️ 7. Mobile Integration (iOS / Android)

Reference material lives in:
```
examples/mobile/qr_scanner_demo.md
```

Includes:
- QR scanning flow
- Base64URL decoding
- canonical JSON rules
- request / response examples

---

# ⭐️ 8. Test Suite & CI

Q-ID is covered by an extensive test suite:

- crypto roundtrips
- tamper detection
- protocol validation
- integration helpers
- hybrid enforcement logic

CI enforces **≥ 90% coverage** and fail-closed behavior.

---

# ⭐️ 9. Threat Model (Planned)

A dedicated threat model document is **planned** and not yet committed.
Security assumptions are currently documented inline and in contract specs.

---

# ⭐️ 10. Migration Path & Future Work

Q-ID is designed for:

- Seamless PQC migration
- Hybrid transition strategies
- Wallet ecosystem expansion
- Future Guardian / Shield signal consumption

These are **architectural guarantees**, not yet active integrations.

---

# ⭐️ 11. Contributing

Q-ID is security-critical software.

All contributions must preserve:
- determinism
- test coverage
- contract correctness
- fail-closed security

See `CONTRIBUTING.md` before opening a PR.

---

# ⭐️ 12. Summary

✔ Cryptographically signed authentication  
✔ PQC-ready architecture  
✔ Hybrid signature support  
✔ Strict service binding  
✔ QR-first workflows  
✔ Adamantine-ready helpers  
✔ Contract-driven design  
✔ Fully tested & CI enforced  

---

**MIT Licensed — @Darek_DGB**  
Quantum-ready. Future-proof. DigiByte-strong.
