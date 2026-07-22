# Q-ID / Shield v4 Crypto Compatibility Contract

Author attribution: DarekDGB

## Status

Compatibility profile: `qid-shield-v4-compatibility-v1`

This document is the frozen Q-ID-side compatibility boundary for Shield v4.
It is integrity-locked by
`contracts/qid_shield_v4_compatibility_manifest_v1.json`.

This contract changes no Q-ID runtime code, cryptographic behavior, public API,
dependency, key material, or verifier policy. It does not add Shield signing or
verification code to Q-ID.

## Purpose and Claim Boundary

Q-ID produces identity and authentication evidence.

Shield v4 produces cryptographically verifiable component-verdict and
Orchestrator-receipt evidence. Shield evidence does not itself grant execution
authority.

AdamantineOS remains the final fail-closed policy and execution boundary.

Q-ID and Shield v4 share accurate algorithm terminology and a fail-closed
philosophy. They do not share key authority, trust registries, signing roles,
canonicalization profiles, domain tags, or verifier policy.

## Q-ID Execution Modes and Algorithm Mapping

Q-ID's default execution mode is its deterministic CI-safe stub. The stub is a
contract and behavior scaffold, not secure PQC.

Only explicit selection of `QID_PQC_BACKEND=liboqs` activates the real Q-ID PQC
backend. In that explicitly selected path, the current runtime mapping is:

| Q-ID identifier | Accurate meaning | Explicit liboqs mapping |
|---|---|---|
| `dev-hmac-sha256` | Deterministic development scaffold only | None |
| `pqc-ml-dsa` | ML-DSA, formerly CRYSTALS-Dilithium | `ML-DSA-44`, with legacy backend label `Dilithium2` as a compatibility fallback |
| `pqc-falcon` | Falcon-family signature evidence | `Falcon-512` |
| `pqc-hybrid-ml-dsa-falcon` | Q-ID hybrid with strict AND semantics | `ML-DSA-44` and `Falcon-512` |

ML-DSA and FN-DSA/Falcon are separate signature directions. FN-DSA is based on
Falcon. Falcon must never be described as ML-DSA.

The legacy identifier `hybrid-dev-ml-dsa` is a Q-ID compatibility alias only.
Shield v4 does not inherit it.

`qid/pqc/keygen_liboqs.py` recognizes additional parameter sets for Q-ID crypto
agility, including `ML-DSA-65`, `ML-DSA-87`, and `Falcon-1024`. Recognition by
a helper allowlist does not select those parameter sets for Q-ID's current
runtime mapping and grants no Shield role, trust, policy, or authority.

The Q-ID implementation sources that define this boundary are:

- `qid/algorithms.py`
- `qid/crypto.py`
- `qid/pqc_backends.py`
- `qid/pqc/keygen_liboqs.py`
- `qid/pqc_sign.py`
- `qid/pqc_verify.py`
- `docs/CONTRACTS/PQC_MODEL.md`
- `docs/CONTRACTS/CANONICAL_JSON_PROFILES.md`

## Shield v4 Verifier Policy

Shield v4 uses this verifier-controlled policy:

```text
policy version: policy.v1
required: classical-ed25519 + ml-dsa
optional: fn-dsa
```

The locked Shield profiles are:

| Policy role | Algorithm | Algorithm family | Standard profile | Mechanism |
|---|---|---|---|---|
| Required classical | `classical-ed25519` | `classical-ed25519` | `rfc8032-ed25519-v1` | Ed25519 |
| Required PQC | `ml-dsa` | `pqc-ml-dsa` | `fips204-ml-dsa-65-v1` | ML-DSA-65 |
| Optional PQC evidence | `fn-dsa` | `pqc-fn-dsa` | `fips206-draft-falcon1024-v1` | Falcon-1024 |

The optional profile is accurately described as **draft FN-DSA/Falcon-1024
evidence**. This contract does not claim final FIPS 206 standard proof.

Optional FN-DSA evidence must never replace Ed25519 or ML-DSA, rescue a failed
required signature, override a required verification failure, weaken verifier
policy, bypass a denial, or become execution authority. Present but malformed
or invalid optional evidence is fatal.

## Parameter-Set and Policy Separation

| Boundary | ML-DSA direction | Falcon / FN-DSA direction | Policy meaning |
|---|---|---|---|
| Q-ID explicit liboqs path | `pqc-ml-dsa` mapped to ML-DSA-44 | `pqc-falcon` mapped to Falcon-512 | Q-ID identity/authentication evidence |
| Shield v4 | required `ml-dsa` using ML-DSA-65 | optional `fn-dsa` using Falcon-1024 | Shield verdict/receipt evidence under verifier-controlled policy |

Q-ID `pqc-falcon` with Falcon-512 is not Shield `fn-dsa` with Falcon-1024.
Q-ID `pqc-ml-dsa` with ML-DSA-44 is not Shield `ml-dsa` with ML-DSA-65.

Parameter-set separation is not the trust boundary by itself. Key role, trust
registry, domain separation, canonicalization profile, evidence schema, and
verifier policy must all match independently and fail closed.

## Key and Trust-Registry Separation

Q-ID keys must not be reused as Shield v4 keys. Shield keys must not be reused
as Q-ID identity keys.

Shield v4 owns independent trust-registry roles:

- `shield_component_adn`
- `shield_component_dqsn`
- `shield_component_guardian_wallet`
- `shield_component_qwg`
- `shield_component_sentinel_ai`
- `shield_orchestrator`

| Domain | Key role | Evidence meaning |
|---|---|---|
| Q-ID | Identity/authentication key | User or device authentication evidence |
| Shield component | Component decision key | Signed component-verdict evidence |
| Shield Orchestrator | Orchestrator aggregation key | Signed Shield receipt evidence |
| AdamantineOS | Final verifier and policy boundary | Final fail-closed execution decision |

A key valid in one row is not valid in another row. A matching algorithm name,
parameter set, field name, or public key does not transfer authority.

## Canonicalization Separation

Q-ID uses its own named profiles:

- `qid-canonical-json-v1`
- `adamantine-qid-canonical-json-v1`

Shield v4 uses its independently frozen profile:

- `shield-v4-canon.v1`

Q-ID canonical bytes must not be accepted as Shield canonical bytes merely
because the decoded values look equal. Any bridge must name and verify the
expected profile explicitly.

This V4.9-G contract does not claim canonical signature-bundle ordering. That
is a separately controlled Shield step.

## Domain Separation

Q-ID login, authentication, binding, and identity-attestation signatures must
never verify as Shield evidence or AdamantineOS final approval.

Shield v4 owns these exact implemented domain tags under `policy.v1`:

- `DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1`
- `DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1`

Q-ID does not own, generate, or authorize those tags.

## Hybrid and Failure Semantics

Q-ID's hybrid mode requires its ML-DSA and Falcon components to pass under
strict AND semantics. That Q-ID behavior does not define Shield verifier
policy.

Shield v4 independently requires every verifier-required algorithm to pass.
It rejects missing, duplicate, unknown, unsupported, malformed, mismatched, or
invalid required evidence. Optional evidence cannot convert failure to success.

Embedded policy is evidence only. It cannot weaken verifier-controlled local
policy.

## Authority and Execution Boundary

Q-ID does not:

- make Shield decisions;
- sign Shield component verdicts;
- sign Shield Orchestrator receipts;
- verify Shield final authority;
- grant Shield execution approval;
- supply Shield trust-registry authority;
- upgrade a Shield `DENY` to `ALLOW`;
- override AdamantineOS policy;
- sign transactions;
- broadcast transactions; or
- change DigiByte consensus.

Shield v4 does not sign transactions, broadcast transactions, change DigiByte
consensus, or grant final execution authority. It produces cryptographically
verifiable decision evidence only.

Cryptographic verification proves evidence under the applicable profile and
trusted key role. It does not create policy or execution authority.

## Runtime Dependency Boundary

The Q-ID runtime has no Shield code dependency. No module under `qid/` imports
Shield component, Shield Orchestrator, or Shield trust-registry code.

This compatibility contract is documentation and integrity metadata only. It
does not create a runtime bridge.

## CI and Live-OQS Claim Boundary

Q-ID standard CI proves its deterministic baseline and coverage gate.

The Q-ID optional-liboqs workflow is intended to exercise Q-ID real-backend
compatibility when explicitly selected. A green run is Q-ID-only repository
evidence, not guarded proof that required live nodes executed, because the
workflow has no exact node-ID and zero-skip guard. It does not prove the
guarded seven-repository Shield real-OQS boundary and does not authorize a
Shield live-OQS claim.

## Fail-Closed Integration Requirements

Any integration using Q-ID and Shield evidence must fail closed on:

- a Q-ID key presented for a Shield role;
- a Shield key presented for a Q-ID role;
- a Q-ID signature presented as Shield evidence;
- a Shield signature presented as Q-ID evidence;
- trust-registry, key-role, domain-tag, schema, profile, or policy mismatch;
- missing required Shield signature paths;
- optional evidence attempting to rescue a required failure;
- weaker embedded policy than verifier-controlled policy; or
- any attempt to treat either evidence family as final execution authority.

## Integrity and Change Control

`contracts/qid_shield_v4_compatibility_manifest_v1.json` hash-locks this
document and `docs/CONTRACTS/INDEX.md`. The manifest does not hash itself.

The dedicated manifest proves deterministic file integrity only. It does not
prove authorship, provenance, authentication, freshness, remote attestation,
honest execution, or authority.

The historical `contracts/manifest_v0_1.json` remains a 17-path selective
manifest frozen at `v1.0.2-contracts-locked`. This compatibility contract is
not added to that historical inventory; only the already-covered index hash is
refreshed after the index's final bytes are settled.
