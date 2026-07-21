from __future__ import annotations

import hashlib
import json

import pytest

from qid.binding import compute_binding_id
from qid.canonical import canonical_json_bytes
from qid.crypto import generate_dev_keypair, sign_payload, verify_payload
from qid.hybrid_key_container import compute_container_hash


POLISH_MESSAGE = "Za\u017c\u00f3\u0142\u0107 g\u0119\u015bl\u0105 ja\u017a\u0144"
POLISH_CITY = "\u0141\u00f3d\u017a"
LOCK_EMOJI = "\U0001f510"
EXPECTED_NON_ASCII_CANONICAL = bytes.fromhex(
    "7b2263697479223a22c581c3b364c5ba222c22656d6f6a69223a22f09f949022"
    "2c226d657373616765223a225a61c5bcc3b3c582c4872067c499c59b6cc48520"
    "6a61c5bac584227d"
)
EXPECTED_NON_ASCII_CANONICAL_SHA256 = (
    "038ddc64c7b8ac202a61d0713d2d853123783f0b3f533f940be9a92a04d1fc07"
)


@pytest.mark.parametrize("bad_float", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_bytes_rejects_non_finite_floats(bad_float: float) -> None:
    with pytest.raises(ValueError):
        canonical_json_bytes({"bad_float": bad_float})


def test_canonical_json_bytes_is_deterministic_across_key_order() -> None:
    left = {
        "z": 1,
        "a": 2,
        "nested": {"b": True, "a": None},
        "items": [3, {"y": 2, "x": 1}],
    }
    right = {
        "items": [3, {"x": 1, "y": 2}],
        "nested": {"a": None, "b": True},
        "a": 2,
        "z": 1,
    }

    b1 = canonical_json_bytes(left)
    b2 = canonical_json_bytes(right)

    assert b1 == b2
    assert b1 == json.dumps(
        right,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def test_canonical_json_bytes_preserves_utf8_non_ascii() -> None:
    payload = {
        "message": POLISH_MESSAGE,
        "city": POLISH_CITY,
        "emoji": LOCK_EMOJI,
    }

    out = canonical_json_bytes(payload)

    assert out == EXPECTED_NON_ASCII_CANONICAL
    assert hashlib.sha256(out).hexdigest() == EXPECTED_NON_ASCII_CANONICAL_SHA256
    assert b"\\u" not in out
    assert POLISH_MESSAGE.encode("utf-8") in out
    assert LOCK_EMOJI.encode("utf-8") in out


def test_sign_and_verify_use_same_canonical_bytes_for_non_ascii_payload() -> None:
    kp = generate_dev_keypair()
    payload = {
        "domain": "example.com",
        "address": "DGB123",
        "message": POLISH_MESSAGE,
        "emoji": LOCK_EMOJI,
        "nested": {"z": 2, "a": 1},
    }

    sig = sign_payload(payload, kp)

    assert verify_payload(dict(reversed(list(payload.items()))), sig, kp) is True


def test_binding_id_is_stable_across_payload_key_order() -> None:
    p1 = {
        "version": "1",
        "type": "binding",
        "domain": "example.com",
        "address": "DGB123",
        "policy": "hybrid",
        "pqc_pubkeys": {"ml_dsa": "PUB1", "falcon": "PUB2"},
        "created_at": 1700000000,
        "expires_at": 1700003600,
    }
    p2 = {
        "expires_at": 1700003600,
        "created_at": 1700000000,
        "pqc_pubkeys": {"falcon": "PUB2", "ml_dsa": "PUB1"},
        "policy": "hybrid",
        "address": "DGB123",
        "domain": "example.com",
        "type": "binding",
        "version": "1",
    }

    assert compute_binding_id(p1) == compute_binding_id(p2)


def test_container_hash_is_stable_across_public_view_key_order() -> None:
    c1 = {
        "v": 1,
        "alg": "pqc-hybrid-ml-dsa-falcon",
        "kid": "kid-1",
        "ml_dsa": {"alg": "pqc-ml-dsa", "public_key": "PUB_ML", "secret_key": "SECRET_ML"},
        "falcon": {"alg": "pqc-falcon", "public_key": "PUB_FA", "secret_key": "SECRET_FA"},
        "container_hash": "placeholder",
    }
    c2 = {
        "container_hash": "different-placeholder",
        "falcon": {"secret_key": "SECRET_FA", "public_key": "PUB_FA", "alg": "pqc-falcon"},
        "ml_dsa": {"secret_key": "SECRET_ML", "alg": "pqc-ml-dsa", "public_key": "PUB_ML"},
        "kid": "kid-1",
        "alg": "pqc-hybrid-ml-dsa-falcon",
        "v": 1,
    }

    assert compute_container_hash(c1) == compute_container_hash(c2)
