<!--
Author: DarekDGB
License: MIT (c) 2025
-->

# Q-ID Canonical JSON Profiles

## Purpose

Q-ID uses deterministic JSON serialization for signing, verification, hashing,
URI payloads, and AdamantineOS proof binding.

This document is the contract table for every named canonical JSON profile used
by Q-ID. The implementation source of truth is:

- `qid/canonical_profiles.py`

No module should invent local `json.dumps(...)` security settings for
security-sensitive bytes. It must use one of the named profiles below.

## Profile table

| Profile | `sort_keys` | `separators` | `ensure_ascii` | `allow_nan` | Used by |
|---|---:|---|---:|---:|---|
| `qid-canonical-json-v1` | `True` | `(",", ":")` | `False` | `False` | Internal Q-ID signing, verification, binding, URI payload, and envelope/hash paths |
| `adamantine-qid-canonical-json-v1` | `True` | `(",", ":")` | `True` | `False` | Q-ID to AdamantineOS proof-hash boundary |

## Invariants

1. Both profiles are deterministic.
2. Both profiles reject `NaN`, `Infinity`, and `-Infinity`.
3. The internal Q-ID profile preserves non-ASCII characters as UTF-8 bytes.
4. The AdamantineOS boundary profile escapes non-ASCII characters for
   cross-runtime proof-hash stability.
5. A future profile change is a contract change and must be documented here,
   tested, and reviewed before release.

## Why two profiles exist

The internal Q-ID profile uses `ensure_ascii=False` so Q-ID can sign and verify
UTF-8 payloads without losing byte clarity.

The AdamantineOS boundary profile uses `ensure_ascii=True` because that boundary
already locked the profile name `adamantine-qid-canonical-json-v1` and requires
stable escaped bytes across runtimes.

The two profiles are intentional. They must remain named, documented, and routed
through `qid/canonical_profiles.py` to prevent future drift.
