from __future__ import annotations

from qid.binding import (
    build_binding_payload,
    compute_binding_id,
    sign_binding,
    verify_binding,
)
from qid.crypto import generate_keypair


def test_binding_sign_and_verify_ok() -> None:
    kp = generate_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="DGB_ADDR_1",
        policy="ml-dsa",
        ml_dsa_pub_b64u="b64u-ml-dsa-pub",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )
    env = sign_binding(payload, kp)
    assert "binding_id" in env and env["binding_id"]
    assert env["binding_id"] == compute_binding_id(payload)
    assert verify_binding(env, kp, expected_domain="example.com", now=101) is True


def test_binding_domain_mismatch_rejects() -> None:
    kp = generate_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="DGB_ADDR_1",
        policy="falcon",
        ml_dsa_pub_b64u=None,
        falcon_pub_b64u="b64u-falcon-pub",
        created_at=100,
        expires_at=None,
    )
    env = sign_binding(payload, kp)
    assert verify_binding(env, kp, expected_domain="evil.com", now=101) is False


def test_binding_expired_rejects() -> None:
    kp = generate_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="DGB_ADDR_1",
        policy="falcon",
        ml_dsa_pub_b64u=None,
        falcon_pub_b64u="b64u-falcon-pub",
        created_at=100,
        expires_at=120,
    )
    env = sign_binding(payload, kp)
    assert verify_binding(env, kp, expected_domain="example.com", now=121) is False


def test_binding_tamper_payload_rejects() -> None:
    kp = generate_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="DGB_ADDR_1",
        policy="ml-dsa",
        ml_dsa_pub_b64u="b64u-ml-dsa-pub",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )
    env = sign_binding(payload, kp)

    # Tamper payload after signing (signature must fail)
    env2 = dict(env)
    tampered = dict(env2["payload"])
    tampered["address"] = "DGB_ADDR_2"
    env2["payload"] = tampered

    assert verify_binding(env2, kp, expected_domain="example.com", now=101) is False


def test_binding_id_mismatch_rejects() -> None:
    kp = generate_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="DGB_ADDR_1",
        policy="ml-dsa",
        ml_dsa_pub_b64u="b64u-ml-dsa-pub",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )
    env = sign_binding(payload, kp)

    env2 = dict(env)
    env2["binding_id"] = "not-the-right-id"
    assert verify_binding(env2, kp, expected_domain="example.com", now=101) is False


def test_binding_hybrid_requires_both_keys() -> None:
    kp = generate_keypair()

    # Missing falcon key for hybrid => should raise at build time
    try:
        _ = build_binding_payload(
            domain="example.com",
            address="DGB_ADDR_1",
            policy="hybrid",
            ml_dsa_pub_b64u="b64u-ml-dsa-pub",
            falcon_pub_b64u=None,
            created_at=100,
            expires_at=None,
        )
        assert False, "expected ValueError"
    except ValueError:
        pass

    # Full hybrid ok
    payload = build_binding_payload(
        domain="example.com",
        address="DGB_ADDR_1",
        policy="hybrid",
        ml_dsa_pub_b64u="b64u-ml-dsa-pub",
        falcon_pub_b64u="b64u-falcon-pub",
        created_at=100,
        expires_at=None,
    )
    env = sign_binding(payload, kp)
    assert verify_binding(env, kp, expected_domain="example.com", now=101) is True
