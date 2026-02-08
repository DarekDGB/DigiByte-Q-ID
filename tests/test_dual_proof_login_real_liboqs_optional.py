from __future__ import annotations

import base64
import os

import pytest

from qid.binding import build_binding_payload
from qid.crypto import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO
from qid.pqc.keygen_liboqs import generate_falcon_keypair, generate_ml_dsa_keypair
from qid.pqc_backends import liboqs_sign
from qid.pqc_verify import canonical_payload_bytes, verify_pqc_login


def _has_oqs() -> bool:
    try:
        import oqs  # noqa: F401
        return True
    except Exception:
        return False


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    """Decode unpadded base64url string back into bytes (deterministic)."""
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_dual_proof_login_real_liboqs_ml_dsa_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    ml_pub, ml_sec = generate_ml_dsa_keypair("ML-DSA-44")

    request = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u=_b64u(ml_pub),
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )

    msg = canonical_payload_bytes(request)
    sig = liboqs_sign(ML_DSA_ALGO, msg, ml_sec)

    response = {"pqc_payload": request, "pqc_alg": ML_DSA_ALGO, "pqc_sig": _b64u(sig)}

    assert verify_pqc_login(request, response) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_dual_proof_login_real_liboqs_falcon_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    fa_pub, fa_sec = generate_falcon_keypair("Falcon-512")

    request = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="falcon",
        ml_dsa_pub_b64u=None,
        falcon_pub_b64u=_b64u(fa_pub),
        created_at=100,
        expires_at=None,
    )

    msg = canonical_payload_bytes(request)
    sig = liboqs_sign(FALCON_ALGO, msg, fa_sec)

    response = {"pqc_payload": request, "pqc_alg": FALCON_ALGO, "pqc_sig": _b64u(sig)}

    assert verify_pqc_login(request, response) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_dual_proof_login_real_liboqs_tamper_pqc_sig_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    ml_pub, ml_sec = generate_ml_dsa_keypair("ML-DSA-44")

    request = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u=_b64u(ml_pub),
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )

    msg = canonical_payload_bytes(request)
    sig = liboqs_sign(ML_DSA_ALGO, msg, ml_sec)
    sig_b64u = _b64u(sig)

    # ✅ Deterministic tamper: mutate decoded signature bytes, not base64 tail.
    sig_bytes = _b64u_decode(sig_b64u)
    tampered_bytes = bytearray(sig_bytes)
    tampered_bytes[len(tampered_bytes) // 2] ^= 0x01  # flip 1 bit in the middle
    tampered = _b64u(bytes(tampered_bytes))

    response = {"pqc_payload": request, "pqc_alg": ML_DSA_ALGO, "pqc_sig": tampered}

    assert verify_pqc_login(request, response) is False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_dual_proof_login_real_liboqs_hybrid_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    ml_pub, ml_sec = generate_ml_dsa_keypair("ML-DSA-44")
    fa_pub, fa_sec = generate_falcon_keypair("Falcon-512")

    request = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="hybrid",
        ml_dsa_pub_b64u=_b64u(ml_pub),
        falcon_pub_b64u=_b64u(fa_pub),
        created_at=100,
        expires_at=None,
    )

    msg = canonical_payload_bytes(request)
    sig_ml = liboqs_sign(ML_DSA_ALGO, msg, ml_sec)
    sig_fa = liboqs_sign(FALCON_ALGO, msg, fa_sec)

    response = {
        "pqc_payload": request,
        "pqc_alg": HYBRID_ALGO,
        "pqc_sig": {"ml_dsa": _b64u(sig_ml), "falcon": _b64u(sig_fa)},
    }

    assert verify_pqc_login(request, response) is True
