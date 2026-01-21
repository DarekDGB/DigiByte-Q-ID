import os
import pytest

from qid.crypto import ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO, generate_keypair, sign_payload, verify_payload
from qid.hybrid_key_container import build_container, encode_container


def _has_oqs() -> bool:
    try:
        import oqs  # type: ignore
        return True
    except Exception:
        return False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_ml_dsa_roundtrip() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    kp = generate_keypair(ML_DSA_ALGO)
    payload = {"x": 1}
    sig = sign_payload(payload, kp)
    assert verify_payload(payload, sig, kp) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_ml_dsa_tamper_fails() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    kp = generate_keypair(ML_DSA_ALGO)
    payload = {"x": 10}
    sig = sign_payload(payload, kp)

    # Tamper payload -> must fail
    assert verify_payload({"x": 11}, sig, kp) is False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_falcon_roundtrip() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    kp = generate_keypair(FALCON_ALGO)
    payload = {"x": 2}
    sig = sign_payload(payload, kp)
    assert verify_payload(payload, sig, kp) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_falcon_wrong_pubkey_fails() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    kp = generate_keypair(FALCON_ALGO)
    kp2 = generate_keypair(FALCON_ALGO)
    payload = {"x": 20}
    sig = sign_payload(payload, kp)

    # Wrong public key -> must fail
    assert verify_payload(payload, sig, kp2) is False


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_hybrid_roundtrip_with_container() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    # Generate real PQC component keys
    kp_ml = generate_keypair(ML_DSA_ALGO)
    kp_fa = generate_keypair(FALCON_ALGO)

    # Build container with BOTH public keys and BOTH secret keys (for this implementation)
    container = build_container(
        kid="test-kid",
        ml_dsa_public_key=kp_ml.public_key,
        falcon_public_key=kp_fa.public_key,
        ml_dsa_secret_key=kp_ml.secret_key,
        falcon_secret_key=kp_fa.secret_key,
    )
    container_b64 = encode_container(container)

    # Hybrid signing uses container, not the hybrid keypair fields
    kp_h = generate_keypair(HYBRID_ALGO)
    payload = {"x": 3}

    sig = sign_payload(payload, kp_h, hybrid_container_b64=container_b64)
    assert verify_payload(payload, sig, kp_h, hybrid_container_b64=container_b64) is True


@pytest.mark.skipif(os.getenv("QID_PQC_TESTS") != "1", reason="QID_PQC_TESTS!=1 (opt-in)")
@pytest.mark.skipif(not _has_oqs(), reason="oqs not installed")
def test_real_liboqs_hybrid_wrong_container_fails() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    kp_ml = generate_keypair(ML_DSA_ALGO)
    kp_fa = generate_keypair(FALCON_ALGO)
    container_ok = build_container(
        kid="test-kid",
        ml_dsa_public_key=kp_ml.public_key,
        falcon_public_key=kp_fa.public_key,
        ml_dsa_secret_key=kp_ml.secret_key,
        falcon_secret_key=kp_fa.secret_key,
    )
    container_bad = build_container(
        kid="test-kid",
        ml_dsa_public_key=kp_ml.public_key,
        falcon_public_key=kp_fa.public_key,
        ml_dsa_secret_key=kp_ml.secret_key,
        falcon_secret_key=generate_keypair(FALCON_ALGO).secret_key,
    )
    b64_ok = encode_container(container_ok)
    b64_bad = encode_container(container_bad)

    kp_h = generate_keypair(HYBRID_ALGO)
    payload = {"x": 30}
    sig = sign_payload(payload, kp_h, hybrid_container_b64=b64_ok)

    # Wrong container -> must fail
    assert verify_payload(payload, sig, kp_h, hybrid_container_b64=b64_bad) is False
