# Q-ID v1.1.0 Release Plan

**Status:** ready once documentation and release surfaces are aligned

---

## Release Intent

`v1.1.0` is the first Q-ID minor release after `v1.0.2`.

Why minor and not patch:

- new integration surface added
- new contract added
- new example/docs added
- Guardian Wallet v3 auth bridge now exists as a public integration boundary

---

## What v1.1.0 Adds

### Added
- `contracts/guardian_qid_auth_request_v1.json`
- `qid/integration/guardian_v3.py`
- strict fail-closed validation for Guardian Wallet v3 auth requests
- regression tests covering deterministic request building and schema validation
- example roundtrip for Q-ID → Guardian Wallet v3 auth flow
- documentation for the new auth bridge

### Preserved
- existing `qid/integration/guardian.py` login event adapter remains unchanged
- Adamantine integration remains unchanged
- cryptographic verification responsibilities remain inside Q-ID

### Not Included
- no transaction execution
- no Guardian policy decision logic inside Q-ID
- no authority expansion
- no breaking protocol changes

---

## Release Sequence

1. Guardian Wallet finalizes first public stable tag as `v3.0.0`
2. Q-ID finalizes docs/examples/release truth
3. Q-ID version surfaces bump to `1.1.0`
4. tag `v1.1.0`

---

## Required Final Checks

- CI green
- coverage 100%
- README aligned with real repo truth
- docs mention Guardian Wallet v3 auth bridge
- no version drift between:
  - `pyproject.toml`
  - `README.md`
  - release notes
  - tag

---

## Version Truth

Current baseline before tag:
- Q-ID codebase includes the Guardian Wallet v3 auth bridge
- tag still pending

Release target:
- `v1.1.0`

---

**Author:** DarekDGB  
**License:** MIT
