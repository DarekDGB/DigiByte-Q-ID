from __future__ import annotations

import base64
import json

import pytest

from qid.crypto import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO
from qid.hybrid_key_container import (
    build_container,
    decode_container,
    encode_container,
    public_view_dict,
    try_decode_container,
)


def _b64(obj: object) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def test_public_view_dict_accepts_plain_dict_input() -> None:
    d = {
        "v": 1,
        "alg": HYBRID_ALGO,
        "kid": "kid",
        "ml_dsa": {"alg": ML_DSA_ALGO, "public_key": "PUB_ML", "secret_key": "SECRET_ML"},
        "falcon": {"alg": FALCON_ALGO, "public_key": "PUB_FA", "secret_key": "SECRET_FA"},
        "container_hash": "ignored-here",
    }
    pv = public_view_dict(d)
    # Secret keys must not appear in public view
    assert pv["ml_dsa"].get("secret_key") is None
    assert pv["falcon"].get("secret_key") is None
    assert pv["ml_dsa"]["alg"] == ML_DSA_ALGO
    assert pv["falcon"]["alg"] == FALCON_ALGO


def test_decode_container_rejects_non_object_json() -> None:
    # base64(JSON string) -> must be object/dict, fail-closed
    s = _b64("not-a-dict")
    with pytest.raises(ValueError):
        decode_container(s)


def test_try_decode_container_fail_closed_on_non_object_json() -> None:
    s = _b64(["list-not-dict"])
    assert try_decode_container(s) is None


def test_encode_container_rejects_missing_components_dicts() -> None:
    good = build_container("kid1", "PUB_ML", "PUB_FA")
    d = {
        "v": 1,
        "alg": HYBRID_ALGO,
        "kid": "kid1",
        "ml_dsa": "not-a-dict",
        "falcon": {"alg": FALCON_ALGO, "public_key": good.falcon.public_key},
        "container_hash": good.container_hash,
    }
    with pytest.raises(ValueError):
        encode_container(d)


def test_encode_container_rejects_secret_key_wrong_type() -> None:
    good = build_container("kid1", "PUB_ML", "PUB_FA")
    d = {
        "v": 1,
        "alg": HYBRID_ALGO,
        "kid": "kid1",
        "ml_dsa": {"alg": ML_DSA_ALGO, "public_key": good.ml_dsa.public_key, "secret_key": 123},
        "falcon": {"alg": FALCON_ALGO, "public_key": good.falcon.public_key},
        "container_hash": good.container_hash,
    }
    with pytest.raises(ValueError):
        encode_container(d)


def test_encode_container_rejects_component_alg_mismatch() -> None:
    good = build_container("kid1", "PUB_ML", "PUB_FA")
    d = {
        "v": 1,
        "alg": HYBRID_ALGO,
        "kid": "kid1",
        "ml_dsa": {"alg": "wrong", "public_key": good.ml_dsa.public_key},
        "falcon": {"alg": FALCON_ALGO, "public_key": good.falcon.public_key},
        "container_hash": good.container_hash,
    }
    with pytest.raises(ValueError):
        encode_container(d)
