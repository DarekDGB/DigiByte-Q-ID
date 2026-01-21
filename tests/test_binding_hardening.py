from __future__ import annotations

from qid.binding import build_binding_payload, sign_binding, verify_binding
from qid.crypto import DEV_ALGO, generate_keypair


def test_binding_rejects_future_created_at() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=200,
        expires_at=None,
    )
    env = sign_binding(payload, kp)

    # created_at is in the future relative to now -> reject
    assert verify_binding(env, kp, expected_domain="example.com", now=100) is False


def test_binding_rejects_expired_binding() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="falcon",
        ml_dsa_pub_b64u=None,
        falcon_pub_b64u="fa",
        created_at=10,
        expires_at=50,
    )
    env = sign_binding(payload, kp)

    # expired -> reject
    assert verify_binding(env, kp, expected_domain="example.com", now=100) is False


def test_binding_rejects_domain_mismatch() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=10,
        expires_at=None,
    )
    env = sign_binding(payload, kp)

    assert verify_binding(env, kp, expected_domain="evil.com", now=11) is False


def test_binding_rejects_missing_payload() -> None:
    kp = generate_keypair(DEV_ALGO)
    env = {"binding_id": "x", "payload": None, "signature": "s", "algorithm": kp.algorithm}
    assert verify_binding(env, kp, expected_domain="example.com", now=10) is False


def test_binding_rejects_missing_signature_fields() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=10,
        expires_at=None,
    )
    env = sign_binding(payload, kp)

    # Remove signature -> reject
    env2 = dict(env)
    env2.pop("signature", None)
    assert verify_binding(env2, kp, expected_domain="example.com", now=11) is False


def test_binding_rejects_tampered_payload_after_signing() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=10,
        expires_at=None,
    )
    env = sign_binding(payload, kp)

    # Tamper payload -> signature must fail -> reject
    tampered = dict(env)
    tp = dict(tampered["payload"])
    tp["domain"] = "evil.com"
    tampered["payload"] = tp
    assert verify_binding(tampered, kp, expected_domain="example.com", now=11) is False


def test_binding_rejects_invalid_now_type() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=10,
        expires_at=None,
    )
    env = sign_binding(payload, kp)

    # now must be int when provided -> reject (fail-closed)
    assert verify_binding(env, kp, expected_domain="example.com", now="11") is False  # type: ignore[arg-type]
