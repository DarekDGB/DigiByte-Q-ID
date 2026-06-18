"""
Canonical JSON serialization helpers for DigiByte Q-ID.

Contract:
- Uses the named qid-canonical-json-v1 profile from qid.canonical_profiles.
- Deterministic output only.
- UTF-8 encoded canonical JSON.
- No per-module serializer drift.

Rules:
- sort_keys=True
- separators=(",", ":")
- ensure_ascii=False
- allow_nan=False
"""

from __future__ import annotations

from typing import Any

from .canonical_profiles import QID_CANONICAL_JSON_V1, canonical_json_bytes_for_profile


def canonical_json_bytes(obj: Any) -> bytes:
    """
    Return canonical UTF-8 JSON bytes for any JSON-serializable object.

    This helper is the public internal-Q-ID wrapper for the
    qid-canonical-json-v1 profile. Boundary-specific profiles, such as
    adamantine-qid-canonical-json-v1, must be selected explicitly through
    qid.canonical_profiles.
    """
    return canonical_json_bytes_for_profile(obj, QID_CANONICAL_JSON_V1)
