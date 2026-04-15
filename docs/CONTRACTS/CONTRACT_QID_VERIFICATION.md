# CONTRACT_QID_VERIFICATION

Status: Locked for v1.0.2  
Owner: DarekDGB  
Scope: Signing and verification truth for DigiByte Q-ID  
Compatibility target: Non-breaking hardening release  

---

## Purpose

This document defines the single source of truth for Q-ID signing and verification behavior.

It exists to prevent drift between:

- implementation
- tests
- docs
- integrations
- release claims

Q-ID does not guess. It verifies.

---

## Security goals

Q-ID verification must remain:

- deterministic
- fail-closed
- explicit
- shape-locked
- algorithm-locked
- non-ambiguous

---

## Canonicalization rules

All security-critical structured payloads must be converted to bytes using canonical JSON with the following exact rules:

- UTF-8 encoding
- `sort_keys=True`
- `separators=(",", ":")`
- `ensure_ascii=False`

Reference implementation path:

- `qid/canonical.py`
- function: `canonical_json_bytes(obj)`

### Invariant QID-VER-001

Every signing and verification path for structured payloads must use the single canonical JSON helper.

---

## Signing bytes rule

For Q-ID payload signing, the signed message bytes are:

```text
canonical_json_bytes(payload)
```

No additional envelope fields are included in the signing bytes.

No transport-layer metadata is included in the signing bytes.

### Included

- the full payload object passed into signing

### Excluded

- signature envelope wrapper
- base64 transport encoding
- container wrapper encoding
- external request context not embedded inside the payload

### Invariant QID-VER-002

Signing bytes must be exactly the canonical JSON bytes of the payload object.

---

## Verification bytes rule

For Q-ID payload verification, the verification message bytes are:

```text
canonical_json_bytes(payload)
```

Verification must be performed against the same payload-byte construction rule as signing.

### Invariant QID-VER-003

Verification bytes must be exactly the canonical JSON bytes of the payload object.

---

## Asymmetry policy

There is no intentional sign/verify payload asymmetry in Q-ID payload signatures.

If a future protocol revision needs sign/verify asymmetry, it must be:

- explicitly versioned
- separately documented
- separately tested
- not introduced silently

### Invariant QID-VER-004

Current Q-ID payload signing and verification are symmetric at the byte-construction layer.

---

## Envelope version rule

Current signature envelope version is:

```text
v = 1
```

Any other envelope version must be rejected.

### Invariant QID-VER-005

Only envelope version `1` is accepted.

---

## Accepted signature envelope shapes

Only the following top-level envelope shapes are valid.

## Shape A â single-signature envelope

Used for:

- `dev-hmac-sha256`
- `pqc-ml-dsa`
- `pqc-falcon`

Shape:

```json
{
  "v": 1,
  "alg": "<single-algorithm-id>",
  "sig": "<base64-signature>"
}
```

Required fields:

- `v`
- `alg`
- `sig`

Forbidden fields for this shape:

- `sigs`

## Shape B â hybrid-signature envelope

Used for:

- `pqc-hybrid-ml-dsa-falcon`

Shape:

```json
{
  "v": 1,
  "alg": "pqc-hybrid-ml-dsa-falcon",
  "sigs": {
    "pqc-ml-dsa": "<base64-signature>",
    "pqc-falcon": "<base64-signature>"
  }
}
```

Required fields:

- `v`
- `alg`
- `sigs`
- `sigs.pqc-ml-dsa`
- `sigs.pqc-falcon`

Forbidden fields for this shape:

- `sig`

### Invariant QID-VER-006

Single-algorithm envelopes must use `sig` and must not use `sigs`.

### Invariant QID-VER-007

Hybrid envelopes must use `sigs` and must not use `sig`.

---

## Accepted algorithm IDs

Public normalized algorithm IDs:

- `dev-hmac-sha256`
- `pqc-ml-dsa`
- `pqc-falcon`
- `pqc-hybrid-ml-dsa-falcon`

Legacy accepted alias:

- `hybrid-dev-ml-dsa`

Legacy alias normalization rule:

```text
hybrid-dev-ml-dsa -> pqc-hybrid-ml-dsa-falcon
```

### Invariant QID-VER-008

Legacy algorithm aliases must normalize before enforcement.

### Invariant QID-VER-009

Any non-allowed algorithm ID must be rejected fail-closed.

---

## Hybrid strict-AND rule

Hybrid verification requires both of the following to verify successfully:

- ML-DSA proof
- Falcon proof

No partial success is accepted.

No short-circuit acceptance is allowed.

### Invariant QID-VER-010

Hybrid verification is strict AND.

---

## Fail-closed rejection rules

Verification must return failure for any of the following:

- invalid base64 envelope transport
- non-object decoded envelope
- wrong envelope version
- unsupported algorithm
- missing required envelope field
- wrong envelope shape for algorithm
- hybrid envelope missing one component
- malformed signature encoding
- invalid hybrid container when required
- backend requested but unavailable
- payload mutation after signing
- domain mismatch in binding verification
- binding time window failure
- binding hash mismatch

### Invariant QID-VER-011

Malformed or ambiguous signature envelopes must be rejected fail-closed.

### Invariant QID-VER-012

Backend selection must never silently downgrade when a real PQC backend was explicitly requested.

---

## Backend policy

Default CI-safe behavior may use stub logic for deterministic tests.

Real PQC backend behavior is opt-in and selected via environment.

If a real PQC backend is explicitly requested and is unavailable or invalid, the system must fail closed.

### Current caution

If CI-safe stub verification semantics differ from true public-key verification semantics, that difference must be treated as implementation debt and must not be described as protocol truth.

### Invariant QID-VER-013

Protocol truth is defined by envelope rules, canonical bytes, and fail-closed behavior Ã¢ÂÂ not by accidental stub shortcuts.

---

## Container rule for hybrid verification

When hybrid verification depends on a hybrid key container:

- the container must decode successfully
- the container algorithm must equal `pqc-hybrid-ml-dsa-falcon`
- required public verification material must be present
- invalid container state must be rejected fail-closed

### Invariant QID-VER-014

Hybrid verification requiring a container must reject invalid or mismatched containers.

---

## Unknown field policy

For v1.0.2 hardening, the intended policy is:

- accept only the defined envelope shapes above
- reject ambiguous mixed shapes
- avoid permissive envelope parsing drift

If unknown-field rejection is not yet fully enforced in code, tests must be added before release truth claims are upgraded.

### Invariant QID-VER-015

Envelope parsing must not accept ambiguous mixed shapes.

---

## Test mapping expectation

Each invariant in this contract must map to at least one deterministic test.

Minimum test groups expected:

- canonical byte lock tests
- single-envelope acceptance tests
- hybrid-envelope acceptance tests
- mixed-shape rejection tests
- wrong-version rejection tests
- wrong-algorithm rejection tests
- strict-AND hybrid rejection tests
- backend fail-closed tests
- binding domain/time/hash rejection tests

---

## Release rule

This contract must be considered the protocol source of truth for v1.0.2 hardening.

No implementation change that alters these rules may be released without:

- contract update
- test update
- changelog entry
- explicit version review

---
