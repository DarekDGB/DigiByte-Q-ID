from __future__ import annotations

import copy

import pytest

from qid.crypto import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO
from qid.hybrid_key_container import (
    build_container,
    compute_container_hash,
    decode_container,
    encode_container,
    try_decode_container,
)


def test_build_container_computes_hash_from_public_view_only() -> None:
    c = build_container(
        kid="wallet-main-2026-01",
        ml_dsa_public_key="PUB_ML",
        falcon_public_key="PUB_FA",
        ml_dsa_secret_key="SECRET_ML",
        falcon_secret_key="SECRET_FA",
    )
    # Hash must match recomputation
    assert c.container_hash == compute_container_hash(
        {
            "v": c.v,
            "alg": c.alg,
            "kid": c.kid,
            "ml_dsa": {"alg": c.ml_dsa.alg, "public_key": c.ml_dsa.public_key, "secret_key": c.ml_dsa.secret_key},
            "falcon": {"alg": c.falcon.alg, "public_key": c.falcon.public_key, "secret_key": c.falcon.secret_key},
            "container_hash": c.container_hash,
        }
    )

    # Changing secret keys must NOT change expected hash (public view only),
    # but it SHOULD fail validation because container_hash would mismatch if recomputed
    d = {
        "v": 1,
        "alg": HYBRID_ALGO,
        "kid": "wallet-main-2026-01",
        "ml_dsa": {"alg": ML_DSA_ALGO, "public_key": "PUB_ML", "secret_key": "DIFF"},
        "falcon": {"alg": FALCON_ALGO, "public_key": "PUB_FA", "secret_key": "DIFF"},
        "container_hash": c.container_hash,
    }
    # same public view -> same hash
    assert compute_container_hash(d) == c.container_hash


def test_encode_decode_roundtrip() -> None:
    c1 = build_container("kid1", "PUB_ML", "PUB_FA")
    enc = encode_container(c1)
    c2 = decode_container(enc)
    assert c2 == c1


def test_try_decode_fail_closed() -> None:
    assert try_decode_container("not-base64") is None


def test_rejects_wrong_version() -> None:
    c = build_container("kid1", "PUB_ML", "PUB_FA")
    enc = encode_container(c)
    # Tamper decoded dict by flipping version inside the encoded payload
    import base64, json

    raw = base64.b64decode(enc.encode("ascii"))
    d = json.loads(raw.decode("utf-8"))
    d["v"] = 2
    tampered = base64.b64encode(json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")).decode("ascii")
    with pytest.raises(ValueError):
        decode_container(tampered)


def test_rejects_wrong_alg() -> None:
    c = build_container("kid1", "PUB_ML", "PUB_FA")
    d = {
        "v": c.v,
        "alg": "wrong",
        "kid": c.kid,
        "ml_dsa": {"alg": ML_DSA_ALGO, "public_key": c.ml_dsa.public_key},
        "falcon": {"alg": FALCON_ALGO, "public_key": c.falcon.public_key},
        "container_hash": c.container_hash,
    }
    with pytest.raises(ValueError):
        encode_container(d)


def test_rejects_missing_component_key() -> None:
    c = build_container("kid1", "PUB_ML", "PUB_FA")
    d = {
        "v": 1,
        "alg": HYBRID_ALGO,
        "kid": "kid1",
        "ml_dsa": {"alg": ML_DSA_ALGO, "public_key": "PUB_ML"},
        "falcon": {"alg": FALCON_ALGO, "public_key": "PUB_FA"},
        "container_hash": c.container_hash,
    }
    d2 = copy.deepcopy(d)
    del d2["ml_dsa"]["public_key"]
    with pytest.raises(ValueError):
        encode_container(d2)


def test_rejects_hash_mismatch() -> None:
    c = build_container("kid1", "PUB_ML", "PUB_FA")
    d = {
        "v": 1,
        "alg": HYBRID_ALGO,
        "kid": "kid1",
        "ml_dsa": {"alg": ML_DSA_ALGO, "public_key": "PUB_ML"},
        "falcon": {"alg": FALCON_ALGO, "public_key": "PUB_FA"},
        "container_hash": "AAAA",  # wrong
    }
    with pytest.raises(ValueError):
        encode_container(d)
