# DigiByte Q-ID — Locked Surface (v0.1)

**Author:** DarekDGB  
**License:** MIT  

This document defines what is **LOCKED** in v0.1.
Changes here require a **major version bump**.

---

## Locked API Surface

### Protocol
- `build_login_request_payload`
- `build_login_response_payload`
- `server_verify_login_response`
- `login`
- `register_identity`

### Binding
- Binding payload structure
- Binding envelope structure
- Binding ID derivation
- Domain normalization rules
- Timestamp validation rules

### PQC
- Algorithm identifiers
- Fail-closed enforcement
- No silent fallback rule

---

## Locked Behavior

- Legacy mode MUST remain Digi-ID compatible
- Dual-proof MUST require binding + PQC
- Missing PQC backend MUST fail dual-proof verification
- Resolver injection via request payload keys only
- Verification never raises (returns False)

---

## Not Locked (May Evolve)

- Additional PQC algorithms
- New protocol versions (v0.2+)
- Wallet UX helpers
- Additional metadata fields (non-critical)

---

## Versioning Rules

- v0.x → breaking allowed with notice
- v1.0 → strict semantic versioning
- Contract tests define truth

---

## Exit Criteria

v0.1 is considered DONE when:
- CI green
- Coverage ≥ 90%
- Contract tests pass
- Spec matches implementation
