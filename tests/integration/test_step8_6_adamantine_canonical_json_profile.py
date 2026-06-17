from __future__ import annotations

import math

import pytest

from qid.integration.adamantine import _canon_json_bytes


def test_adamantine_canonical_json_profile_rejects_nan_and_infinity() -> None:
    for value in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError, match="Out of range float values"):
            _canon_json_bytes({"unsafe_number": value})


def test_adamantine_canonical_json_profile_is_exact_stable_bytes() -> None:
    payload = {"z": "£", "a": {"b": True}, "n": 1}

    assert _canon_json_bytes(payload) == b'{"a":{"b":true},"n":1,"z":"\\u00a3"}'
