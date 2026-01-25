from __future__ import annotations

import base64
import os

import pytest

from qid.crypto import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO, QIDKeyPair, sign_payload, verify_payload
from qid.hybrid_key_container import build_container, encode_container
from qid.pqc.keygen_liboqs import generate_falcon_keypair, generate_ml_dsa_keypair


def _has_oqs() -> bool:
    try:
        import oqs  # noqa: F401
        return True
    except Exception:
        return False


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_ml_dsa_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    pub, sec = generate_ml_dsa_keypair("ML-DSA-44")
    kp = QIDKeyPair(algorithm=ML_DSA_ALGO, public_key=_b64(pub), secret_key=_b64(sec))

    payload = {"x": 1}
    sig = sign_payload(payload, kp)
    assert verify_payload(payload, sig, kp) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_ml_dsa_tamper_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    pub, sec = generate_ml_dsa_keypair("ML-DSA-44")
    kp = QIDKeyPair(algorithm=ML_DSA_ALGO, public_key=_b64(pub), secret_key=_b64(sec))

    payload = {"x": 10}
    sig = sign_payload(payload, kp)

    assert verify_payload({"x": 11}, sig, kp) is False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_falcon_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    pub, sec = generate_falcon_keypair("Falcon-512")
    kp = QIDKeyPair(algorithm=FALCON_ALGO, public_key=_b64(pub), secret_key=_b64(sec))

    payload = {"x": 2}
    sig = sign_payload(payload, kp)
    assert verify_payload(payload, sig, kp) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_falcon_wrong_pubkey_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    pub1, sec1 = generate_falcon_keypair("Falcon-512")
    pub2, _sec2 = generate_falcon_keypair("Falcon-512")

    kp_sign = QIDKeyPair(algorithm=FALCON_ALGO, public_key=_b64(pub1), secret_key=_b64(sec1))
    kp_verify_wrong = QIDKeyPair(algorithm=FALCON_ALGO, public_key=_b64(pub2), secret_key=_b64(sec1))

    payload = {"x": 20}
    sig = sign_payload(payload, kp_sign)

    assert verify_payload(payload, sig, kp_verify_wrong) is False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_hybrid_roundtrip_with_container(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    ml_pub, ml_sec = generate_ml_dsa_keypair("ML-DSA-44")
    fa_pub, fa_sec = generate_falcon_keypair("Falcon-512")

    container = build_container(
        kid="test-kid",
        ml_dsa_public_key=_b64(ml_pub),
        falcon_public_key=_b64(fa_pub),
        ml_dsa_secret_key=_b64(ml_sec),
        falcon_secret_key=_b64(fa_sec),
    )
    container_b64 = encode_container(container)

    dummy = QIDKeyPair(algorithm=HYBRID_ALGO, public_key=_b64(b"dummy"), secret_key=_b64(b"dummy"))

    payload = {"x": 3}
    sig = sign_payload(payload, dummy, hybrid_container_b64=container_b64)

    assert verify_payload(payload, sig, dummy, hybrid_container_b64=container_b64) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_hybrid_wrong_container_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    ml_pub, ml_sec = generate_ml_dsa_keypair("ML-DSA-44")
    fa_pub, fa_sec = generate_falcon_keypair("Falcon-512")

    container_ok = build_container(
        kid="test-kid",
        ml_dsa_public_key=_b64(ml_pub),
        falcon_public_key=_b64(fa_pub),
        ml_dsa_secret_key=_b64(ml_sec),
        falcon_secret_key=_b64(fa_sec),
    )
    ok_b64 = encode_container(container_ok)

    bad_b64 = ok_b64[:-1] + ("A" if ok_b64[-1] != "A" else "B")

    dummy = QIDKeyPair(algorithm=HYBRID_ALGO, public_key=_b64(b"dummy"), secret_key=_b64(b"dummy"))
    payload = {"x": 9}

    sig = sign_payload(payload, dummy, hybrid_container_b64=ok_b64)
    assert verify_payload(payload, sig, dummy, hybrid_container_b64=bad_b64) is False
