"""
Canonical JSON profile registry for DigiByte Q-ID.

This module is the single table that names every security-relevant
JSON canonicalization profile used by Q-ID.

Current profiles:
- qid-canonical-json-v1: internal Q-ID signing, verification, binding,
  URI payload, and envelope/hash paths. Keeps UTF-8 characters as UTF-8.
- adamantine-qid-canonical-json-v1: Q-ID <-> AdamantineOS boundary profile.
  Escapes non-ASCII bytes for cross-runtime stability.

Both profiles are deterministic and reject NaN / Infinity / -Infinity.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CanonicalJsonProfile:
    """Immutable descriptor for a Q-ID canonical JSON profile."""

    name: str
    ensure_ascii: bool
    purpose: str


QID_CANONICAL_JSON_V1 = CanonicalJsonProfile(
    name="qid-canonical-json-v1",
    ensure_ascii=False,
    purpose="Internal Q-ID signing, verification, binding, URI payload, and envelope/hash paths.",
)

ADAMANTINE_QID_CANONICAL_JSON_V1 = CanonicalJsonProfile(
    name="adamantine-qid-canonical-json-v1",
    ensure_ascii=True,
    purpose="Q-ID to AdamantineOS proof-hash boundary profile.",
)


def canonical_json_bytes_for_profile(obj: Any, profile: CanonicalJsonProfile) -> bytes:
    """Return deterministic canonical JSON bytes for the selected named profile."""

    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=profile.ensure_ascii,
        allow_nan=False,
    ).encode("utf-8")
