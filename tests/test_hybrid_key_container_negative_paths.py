from __future__ import annotations

import pytest

from qid.hybrid_key_container import build_container, from_dict, to_dict


def test_from_dict_rejects_invalid_kid() -> None:
    good = build_container("kid1", "PUB_ML", "PUB_FA")
    d = to_dict(good)
    d["kid"] = ""  # invalid -> hits validation branch
    with pytest.raises(ValueError):
        from_dict(d)


def test_from_dict_rejects_falcon_alg_mismatch() -> None:
    good = build_container("kid1", "PUB_ML", "PUB_FA")
    d = to_dict(good)
    d["falcon"]["alg"] = "wrong"
    with pytest.raises(ValueError):
        from_dict(d)


def test_from_dict_rejects_missing_falcon_public_key() -> None:
    good = build_container("kid1", "PUB_ML", "PUB_FA")
    d = to_dict(good)
    d["falcon"]["public_key"] = ""
    with pytest.raises(ValueError):
        from_dict(d)


def test_from_dict_rejects_missing_container_hash() -> None:
    good = build_container("kid1", "PUB_ML", "PUB_FA")
    d = to_dict(good)
    d["container_hash"] = ""
    with pytest.raises(ValueError):
        from_dict(d)
