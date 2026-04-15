# DigiByte Q-ID — Locked Surface (v1.0.2)

**Author:** DarekDGB  
**License:** MIT

This document defines what is **LOCKED** in v1.0.2.
Changes here require either a major contract change or an explicitly versioned new surface.

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
- Explicit backend opt-in semantics

### Verification
- Canonical signing / verification byte rules
- Accepted signature shapes only
- Hybrid strict-AND enforcement

---

## Locked Behavior

- Legacy mode MUST remain Digi-ID compatible
- Dual-proof MUST require binding + PQC
- Missing PQC backend MUST fail dual-proof verification
- Explicit real-backend request MUST fail closed if unavailable
- Resolver injection via request payload keys only
- Verification never raises (returns False)
- Container hash excludes secret material

---

## Not Locked (May Evolve)

- Additional PQC algorithms
- New protocol versions with explicit versioning
- Wallet UX helpers
- Additional metadata fields that are non-critical

---

## Versioning Rules

- v1.x patch releases must remain non-breaking
- Contract tests define truth
- Any breaking serialized-format or verification change requires a new contract/version boundary

---

## Exit Criteria

v1.0.2 is considered release-ready when:
- CI is green
- Tier 1 deterministic coverage remains 100%
- Contract tests pass
- Spec matches implementation
- Optional Tier 2 PQC proof remains green when invoked
