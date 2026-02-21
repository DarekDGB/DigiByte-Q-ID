from qid.binding import build_binding_payload, sign_binding, verify_binding
from qid.crypto import generate_dev_keypair


def test_verify_binding_rejects_created_at_in_future() -> None:
    kp = generate_dev_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="AAEC",
        falcon_pub_b64u=None,
        created_at=200,
        expires_at=None,
    )
    env = sign_binding(payload, kp)
    assert verify_binding(env, kp, expected_domain="example.com", now=100) is False


def test_verify_binding_rejects_expired_expires_at() -> None:
    kp = generate_dev_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="AAEC",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=150,
    )
    env = sign_binding(payload, kp)
    assert verify_binding(env, kp, expected_domain="example.com", now=200) is False


def test_verify_binding_allows_unexpired_expires_at_branch() -> None:
    kp = generate_dev_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="AAEC",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=200,
    )
    env = sign_binding(payload, kp)
    assert verify_binding(env, kp, expected_domain="example.com", now=150) is True
