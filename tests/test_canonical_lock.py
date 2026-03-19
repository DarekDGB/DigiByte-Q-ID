from __future__ import annotations

import json

from qid.binding import compute_binding_id
from qid.canonical import canonical_json_bytes
from qid.crypto import generate_dev_keypair, sign_payload, verify_payload
from qid.hybrid_key_container import compute_container_hash


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
    payload = {"message": "Zażółć gęślą jaźń", "city": "Łódź", "emoji": "🔐"}

    out = canonical_json_bytes(payload)

    assert out == json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert b"\\u" not in out
    assert "Zażółć gęślą jaźń".encode("utf-8") in out
    assert "🔐".encode("utf-8") in out


def test_sign_and_verify_use_same_canonical_bytes_for_non_ascii_payload() -> None:
    kp = generate_dev_keypair()
    payload = {
        "domain": "example.com",
        "address": "DGB123",
        "message": "Zażółć gęślą jaźń",
        "emoji": "🔐",
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
