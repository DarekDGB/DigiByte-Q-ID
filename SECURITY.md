<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# 🔐 Security Policy — DigiByte Q-ID

## Scope

This document defines the **security policy** for the DigiByte Q-ID repository.

It applies to:
- Core protocol logic
- Cryptographic signing and verification
- PQC and hybrid backends
- CI enforcement and fail-closed behavior
- Documentation and contracts that affect security guarantees

Q-ID is **security‑critical software**.

---

## Supported Versions

Only the latest **ci-locked** release is considered supported.

| Version | Status |
|-------|--------|
| v0.1.1-ci-locked | ✅ Supported |
| Older tags | ❌ Unsupported |

Security issues discovered in unsupported versions **will not** be patched.

---

## Security Guarantees

Q-ID is designed around the following non-negotiable principles:

- **Fail-closed by default**  
  Any invalid, malformed, missing, or downgraded input causes verification failure.

- **No silent cryptographic fallback**  
  If a real PQC backend is required and unavailable, operations fail explicitly.

- **Deterministic signing & verification**  
  Canonical JSON encoding is enforced across all cryptographic operations.

- **Explicit algorithm binding**  
  Every signature is bound to a declared algorithm identifier.

- **Hybrid means AND, never OR**  
  Hybrid signatures require *all* components to verify successfully.

- **CI-enforced invariants**  
  Security properties are locked by automated tests and coverage gates.

---

## Out of Scope

The following are explicitly **out of scope** for Q-ID:

- Wallet key custody and storage
- UI/UX security
- Transport security (HTTPS, TLS)
- Session management after authentication
- User device compromise
- Hardware wallet implementations

Q-ID produces **signed authentication events**.  
How they are stored, transported, or acted upon is the responsibility of integrators.

---

## Reporting a Vulnerability

If you discover a security issue:

1. **Do not open a public issue**
2. Do **not** disclose details publicly
3. Contact the maintainer privately

### Contact

- GitHub: @DarekDGB  
- Preferred channel: private GitHub message

Please include:
- Clear description of the issue
- Impact assessment
- Reproduction steps (if possible)
- Suggested mitigation (optional)

---

## Response Process

Valid security reports will be:

1. Acknowledged privately
2. Reproduced and assessed
3. Fixed with a regression test
4. Released in a new **ci-locked** tag
5. Documented in release notes

No fix is considered complete without **tests and CI validation**.

---

## Security Review Expectations

All contributions must:

- Preserve existing security invariants
- Add tests for new security-relevant behavior
- Avoid broad exception catching
- Avoid implicit defaults or fallbacks
- Maintain deterministic behavior

Pull requests that weaken security guarantees **will be rejected**.

---

## Philosophy

> Security is not a feature.  
> It is an invariant.

Q-ID is designed to survive:
- cryptographic transitions
- ecosystem evolution
- future threat models

Changes are intentional.  
Silence is failure.  
Explicit rejection is safety.

---

**MIT Licensed — @DarekDGB**  
Quantum‑ready. Deterministic. Fail‑closed.
