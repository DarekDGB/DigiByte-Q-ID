"""
Canonical JSON serialization helpers for DigiByte Q-ID.

Contract:
- One source of truth for security-critical JSON -> bytes conversion.
- Deterministic output only.
- UTF-8 encoded canonical JSON.
- No per-module serializer drift.

Rules:
- sort_keys=True
- separators=(",", ":")
- ensure_ascii=False
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json_bytes(obj: Any) -> bytes:
    """
    Return canonical UTF-8 JSON bytes for any JSON-serializable object.

    This helper is the single source of truth for security-critical
    structured-data serialization across Q-ID signing, verification,
    binding, and envelope/hash paths.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
