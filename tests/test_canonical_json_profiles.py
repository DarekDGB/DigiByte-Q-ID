from __future__ import annotations

import math

import pytest

from qid.canonical import canonical_json_bytes
from qid.canonical_profiles import (
    ADAMANTINE_QID_CANONICAL_JSON_V1,
    QID_CANONICAL_JSON_V1,
    canonical_json_bytes_for_profile,
)
from qid.integration.adamantine import _canon_json_bytes


def test_named_canonical_json_profiles_are_locked() -> None:
    assert QID_CANONICAL_JSON_V1.name == "qid-canonical-json-v1"
    assert QID_CANONICAL_JSON_V1.ensure_ascii is False
    assert "Internal Q-ID" in QID_CANONICAL_JSON_V1.purpose

    assert ADAMANTINE_QID_CANONICAL_JSON_V1.name == "adamantine-qid-canonical-json-v1"
    assert ADAMANTINE_QID_CANONICAL_JSON_V1.ensure_ascii is True
    assert "AdamantineOS" in ADAMANTINE_QID_CANONICAL_JSON_V1.purpose


def test_internal_and_adamantine_profiles_intentionally_differ_for_non_ascii() -> None:
    payload = {"z": "£", "a": {"b": True}, "n": 1}

    internal = canonical_json_bytes_for_profile(payload, QID_CANONICAL_JSON_V1)
    adamantine = canonical_json_bytes_for_profile(payload, ADAMANTINE_QID_CANONICAL_JSON_V1)

    assert internal == b'{"a":{"b":true},"n":1,"z":"\xc2\xa3"}'
    assert adamantine == b'{"a":{"b":true},"n":1,"z":"\\u00a3"}'
    assert internal != adamantine


def test_public_internal_canonical_wrapper_uses_named_internal_profile() -> None:
    payload = {"z": "£", "a": 1}

    assert canonical_json_bytes(payload) == canonical_json_bytes_for_profile(
        payload,
        QID_CANONICAL_JSON_V1,
    )


def test_adamantine_canonical_wrapper_uses_named_boundary_profile() -> None:
    payload = {"z": "£", "a": 1}

    assert _canon_json_bytes(payload) == canonical_json_bytes_for_profile(
        payload,
        ADAMANTINE_QID_CANONICAL_JSON_V1,
    )


@pytest.mark.parametrize("bad_float", [math.nan, math.inf, -math.inf])
def test_all_named_profiles_reject_non_finite_floats(bad_float: float) -> None:
    for profile in (QID_CANONICAL_JSON_V1, ADAMANTINE_QID_CANONICAL_JSON_V1):
        with pytest.raises(ValueError, match="Out of range float values"):
            canonical_json_bytes_for_profile({"unsafe_number": bad_float}, profile)


def test_canonical_json_profile_registry_is_documented() -> None:
    doc = __import__("pathlib").Path("docs/CONTRACTS/CANONICAL_JSON_PROFILES.md").read_text(
        encoding="utf-8"
    )
    index = __import__("pathlib").Path("docs/CONTRACTS/INDEX.md").read_text(encoding="utf-8")
    integration_doc = __import__("pathlib").Path("docs/qid-adamantine-integration.md").read_text(
        encoding="utf-8"
    )

    assert "`qid-canonical-json-v1`" in doc
    assert "`adamantine-qid-canonical-json-v1`" in doc
    assert "`ensure_ascii=True`" in integration_doc
    assert "CANONICAL_JSON_PROFILES.md" in index
