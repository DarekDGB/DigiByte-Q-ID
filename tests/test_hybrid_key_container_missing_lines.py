import json
import pytest

from qid.hybrid_key_container import build_container, decode_container, to_dict, encode_container


def test_container_rejects_ml_secret_key_wrong_type() -> None:
    c = build_container("kid1", "PUB_ML", "PUB_FA")
    d = to_dict(c)

    d["ml_dsa"]["secret_key"] = 123  # wrong type
    with pytest.raises(ValueError, match="ml_dsa\\.secret_key wrong type"):
        encode_container(d)


def test_container_rejects_missing_components() -> None:
    c = build_container("kid1", "PUB_ML", "PUB_FA")
    d = to_dict(c)

    d.pop("falcon")
    with pytest.raises(ValueError, match="Missing components"):
        encode_container(d)


def test_container_rejects_ml_alg_mismatch() -> None:
    c = build_container("kid1", "PUB_ML", "PUB_FA")
    d = to_dict(c)

    d["ml_dsa"]["alg"] = "wrong"
    with pytest.raises(ValueError, match="ml_dsa\\.alg mismatch"):
        encode_container(d)


def test_decode_container_rejects_non_object_json() -> None:
    # decode_container expects base64->json->dict; if json is list => ValueError at line 242.
    raw = json.dumps([1, 2, 3]).encode("utf-8")

    # reuse internal base64 encoding by encoding a dict first, then swap payload:
    # easiest stable way: take any valid container, then replace decoded bytes is messy;
    # so we build the base64 ourselves:
    import base64

    b64 = base64.b64encode(raw).decode("ascii")
    with pytest.raises(ValueError, match="Container JSON must be an object"):
        decode_container(b64)
