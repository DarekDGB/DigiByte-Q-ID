import base64
import json
import pytest

from qid.crypto import (
    DEV_ALGO,
    HYBRID_ALGO,
    ML_DSA_ALGO,
    FALCON_ALGO,
    _LEGACY_HYBRID_ALGO,  # intentional: we want to cover legacy mapping
    generate_keypair,
    sign_payload,
    verify_payload,
)


def _b64(obj) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def test_sign_rejects_unknown_algorithm() -> None:
    kp = generate_keypair(DEV_ALGO)
    bad = kp.__class__(algorithm="nope", secret_key=kp.secret_key, public_key=kp.public_key)
    with pytest.raises(ValueError):
        sign_payload({"x": 1}, bad)


def test_verify_rejects_non_b64_signature_string() -> None:
    kp = generate_keypair(DEV_ALGO)
    assert verify_payload({"x": 1}, "%%%notbase64%%%", kp) is False


def test_verify_rejects_non_dict_envelope() -> None:
    kp = generate_keypair(DEV_ALGO)
    sig = base64.b64encode(b'"hello"').decode("ascii")  # JSON string, not dict
    assert verify_payload({"x": 1}, sig, kp) is False


def test_verify_rejects_wrong_version() -> None:
    kp = generate_keypair(DEV_ALGO)
    env = {"v": 999, "alg": DEV_ALGO, "sig": "AA=="}
    assert verify_payload({"x": 1}, _b64(env), kp) is False


def test_verify_rejects_alg_not_string() -> None:
    kp = generate_keypair(DEV_ALGO)
    env = {"v": 1, "alg": 123, "sig": "AA=="}
    assert verify_payload({"x": 1}, _b64(env), kp) is False


def test_verify_rejects_alg_mismatch() -> None:
    kp_dev = generate_keypair(DEV_ALGO)
    kp_pqc = generate_keypair(ML_DSA_ALGO)
    sig = sign_payload({"x": 1}, kp_dev)
    assert verify_payload({"x": 1}, sig, kp_pqc) is False


def test_verify_rejects_missing_sig_field_for_non_hybrid() -> None:
    kp = generate_keypair(DEV_ALGO)
    env = {"v": 1, "alg": DEV_ALGO}  # no "sig"
    assert verify_payload({"x": 1}, _b64(env), kp) is False


def test_verify_rejects_bad_sig_base64_for_non_hybrid() -> None:
    kp = generate_keypair(DEV_ALGO)
    env = {"v": 1, "alg": DEV_ALGO, "sig": "%%%bad%%%"}
    assert verify_payload({"x": 1}, _b64(env), kp) is False


def test_verify_rejects_hybrid_missing_sigs_dict() -> None:
    kp = generate_keypair(HYBRID_ALGO)
    env = {"v": 1, "alg": HYBRID_ALGO, "sig": "AA=="}  # wrong field for hybrid
    assert verify_payload({"x": 1}, _b64(env), kp) is False


def test_verify_rejects_hybrid_wrong_keys() -> None:
    kp = generate_keypair(HYBRID_ALGO)
    env = {"v": 1, "alg": HYBRID_ALGO, "sigs": {ML_DSA_ALGO: "AA=="}}  # missing falcon
    assert verify_payload({"x": 1}, _b64(env), kp) is False


def test_verify_rejects_hybrid_bad_b64_inside_sigs() -> None:
    kp = generate_keypair(HYBRID_ALGO)
    env = {
        "v": 1,
        "alg": HYBRID_ALGO,
        "sigs": {ML_DSA_ALGO: "AA==", FALCON_ALGO: "%%%bad%%%"},
    }
    assert verify_payload({"x": 1}, _b64(env), kp) is False


def test_legacy_hybrid_alg_is_normalized() -> None:
    # Use a legacy algorithm label in the keypair and verify we still accept it
    kp = generate_keypair(HYBRID_ALGO)
    legacy_kp = kp.__class__(algorithm=_LEGACY_HYBRID_ALGO, secret_key=kp.secret_key, public_key=kp.public_key)

    payload = {"type": "t", "n": 1}
    sig = sign_payload(payload, legacy_kp)
    assert verify_payload(payload, sig, legacy_kp) is True
