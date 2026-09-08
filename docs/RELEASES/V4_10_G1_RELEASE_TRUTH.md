# Q-ID V4.10-G1 Compatibility Release Truth

Author attribution: DarekDGB
License: MIT
Evidence date: 2026-09-08

## Status and version decision

G1 is a documentation/test candidate. Its post-commit CI and fresh-ZIP gates
remain pending until the complete copy set is uploaded and verified.
It does not declare a new release or guarded Q-ID live-OQS proof.

| Surface | Verified meaning |
|---|---|
| Package distribution | `digibyte-q-id`, metadata `1.1.0` |
| Existing published tag | `v1.1.0` at `4b753030bbf0a267931389c27f01bd05a3afc407` |
| Authenticated source | `eceb0e7e7a291a945a0c8063139474937796171f`, 50 commits ahead of that tag |
| G1 decision | Deliberate no-bump for documentation and tests; retain `1.1.0` |
| Next independent release | Number unassigned; no tag creation or movement in G1 |

Q-ID has no runtime `__version__` or `server_version` surface. Package metadata
is already consistent with the public v1.1.0 baseline. The later working tree
must not be described as the exact published-tag snapshot. Q-ID does not
inherit the Shield `v4.0.0` release number. The
[v1.1.0 plan](../qid-v1.1.0-release-plan.md) is now explicitly historical.

## Source authentication

- Source archive: `DigiByte-Q-ID-main(20260812-060640).zip`.
- ZIP SHA-256: `ffe4b45d6be205150bb282ee5067bfbd7d4f901bcbfc0e639fe0e65bc3782fe6`.
- 168 source files, 16 directories, 184 ZIP entries; safe paths and CRC verified.
- Reconstructed and official Git tree: `7edd99ce0b0547d6a82406ea18011f52c81cdc94`.
- Both available post-V4.9 Q-ID archives are byte-identical; their commit still
  matches current `main` at the evidence check.

The source commit's successful standard
[tests #580](https://github.com/DarekDGB/DigiByte-Q-ID/actions/runs/29921820511)
and optional
[PQC #448](https://github.com/DarekDGB/DigiByte-Q-ID/actions/runs/34199551417)
are source evidence only. They do not close the future G1 commit's gates.

## Frozen compatibility and authority boundary

The normative [Q-ID / Shield alignment contract](../CONTRACTS/QID_SHIELD_V4_CRYPTO_ALIGNMENT.md)
remains byte-identical at SHA-256
`55078028534ebf2d8312b59a9d712053b2e97ebbc56da3b810ce0608f86efdee`.
Its profile is `qid-shield-v4-compatibility-v1`. The compatibility manifest,
historical 17-path manifest, covered contract index, and existing compatibility
tests are unchanged. Both manifests' covered bytes are recomputed and verified;
no covered path changes and no manifest refresh is needed.

| Domain | Runtime mapping / role | Authority limit |
|---|---|---|
| Q-ID default | Deterministic stub | Development scaffold, not secure PQC |
| Q-ID explicit liboqs | `pqc-ml-dsa` -> ML-DSA-44; `pqc-falcon` -> Falcon-512 | Identity/authentication evidence |
| Q-ID hybrid | `pqc-hybrid-ml-dsa-falcon`, strict AND | Both Q-ID components must verify |
| Shield v4 | Required Ed25519 + ML-DSA-65, optional draft FN-DSA/Falcon-1024 | Component-verdict and receipt evidence |
| AdamantineOS | Independent final fail-closed policy and execution boundary | Q-ID evidence cannot override local policy |

Q-ID does not verify Shield cryptography or grant execution authority. Its
Guardian v3 auth bridge builds an auth request, not a Shield receipt verifier.
Identity keys and Shield decision keys, trust registries, domains, schemas,
canonical profiles, and verifier policies remain separate. Q-ID runtime has
no Shield dependency. A helper's support for additional parameter sets does
not transfer a Shield role or trust authority.

`qid-canonical-json-v1` and `adamantine-qid-canonical-json-v1` remain distinct
from `shield-v4-canon.v1`. Optional Shield FN-DSA cannot replace either required
signature, rescue a failure, or weaken policy. This document makes no final
FIPS 206 certification claim. These are preserved boundaries, not new runtime
features or a new production integration.

## Test and workflow evidence

| Gate | Result or requirement |
|---|---|
| Source, local CPython 3.11.15 | 619 passed, 12 expected optional-OQS skips |
| G1 candidate, local CPython 3.11.15 | 625 passed, 12 expected optional-OQS skips |
| Statement coverage | 1662/1662, 100% |
| Branch coverage | 702/702, 100% |
| G1 release-truth tests | 6 passed |
| Post-commit standard workflow | `tests`, complete suite with unchanged 100% gate |
| Post-commit optional workflow | `PQC Optional (liboqs real backend)`, separate successful run on the same commit |

Use the committed standard command, `python -m pytest`, after editable install.
Local verification leaves ordinary bytecode, coverage output, and editable
metadata enabled. The copy-file check scans its exact six controlled paths;
it does not reject generated files. The existing repository-wide UTF-8,
C1-control, attribution, manifest, and runtime-separation checks remain active.

The 12 ordinary skipped tests are in:

- `tests/pqc/test_keygen_liboqs.py` (2);
- `tests/test_dual_proof_login_real_liboqs_optional.py` (4);
- `tests/test_pqc_real_liboqs_optional.py` (6).

Native OQS is unavailable in the local G1 environment. Those skips are not
passing native tests. The optional workflow selects `QID_PQC_BACKEND=liboqs`
and `QID_PQC_TESTS=1`, builds floating native dependencies, and runs the full
suite. It has no exact node-ID and zero-skip guard. A green run alone does not
prove every intended native node executed. G1 makes no guarded Q-ID live-OQS
or seven-repository Shield live-OQS claim and does not add such a workflow.

Coverage is a code-exercise metric, not proof of production security, private
key custody, durable replay storage, or deployed wallet behavior. Services
remain responsible for nonce issuance, replay state, key handling, and policy.

## Exact copy scope

2 NEW / 4 REPLACE / 0 DELETE; 164 unrelated source files remain byte-identical.

NEW:

- `docs/RELEASES/V4_10_G1_RELEASE_TRUTH.md`
- `tests/test_v410g1_release_truth.py`

REPLACE:

- `README.md`
- `CHANGELOG.md`
- `SECURITY.md`
- `docs/qid-v1.1.0-release-plan.md`

All six copy files use ASCII and LF for manual transfer. G1 changes no runtime,
workflow, dependency, pyproject, protocol, schema, fixture, existing test,
manifest, license, or third-party notice bytes. Original changelog history is
preserved with equivalent ASCII typography; static success badges and broad
public claims are replaced with bounded, dated evidence.

First-party attribution remains DarekDGB only. The unchanged
[third-party notices](../../THIRD_PARTY_NOTICES.md) classify external projects
and licenses separately; they are not rewritten as first-party attribution.

## Completion gate

Upload the complete six-file set and commit it together. Standard `tests`
runs on push. The optional workflow also triggers because `tests/**` changes;
dispatch it manually on the final commit if needed. Standard `tests` has no
manual-dispatch control. Verify both final-commit runs and provide a fresh
Q-ID ZIP for exact scope, hashes, test/coverage, encoding, and boundary checks.

Only that fresh-ZIP verification completes G1. G2 Adaptive Core and G3 AI
Gateway follow separately; later final-evidence and release-decision steps
remain pending. No release tag is created or moved by this package.
