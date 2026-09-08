# Q-ID v1.1.0 Release Plan

**Status:** historical release plan; v1.1.0 tag exists

Verified on 2026-09-08: tag `v1.1.0` points to
`4b753030bbf0a267931389c27f01bd05a3afc407`. The authenticated G1 source
`eceb0e7e7a291a945a0c8063139474937796171f` is 50 commits ahead of that tag.
The sequence below records the original release intent, not pending work.
For current compatibility evidence and post-commit gates, see
[V4.10-G1 release truth](RELEASES/V4_10_G1_RELEASE_TRUTH.md).

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
- example roundtrip for Q-ID -> Guardian Wallet v3 auth flow
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

## Historical Release Sequence

1. Guardian Wallet finalizes first public stable tag as `v3.0.0`
2. Q-ID finalizes docs/examples/release truth
3. Q-ID version surfaces bump to `1.1.0`
4. tag `v1.1.0`

---

## Original Final Checks

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

Published snapshot:
- `v1.1.0` is an existing tag, not a pending target.
- The tag identifies its own historical commit, not the later working tree.

V4.10-G1 working-tree decision:
- retain package `1.1.0` for this documentation/test-only step;
- preserve the Guardian v3 bridge, frozen contracts, and runtime bytes;
- assign no next release number and create or move no tag;
- keep Q-ID release versioning independent of Shield `v4.0.0`.

---

**Author:** DarekDGB
**License:** MIT
