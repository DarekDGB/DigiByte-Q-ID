from qid.binding import build_binding_payload, compute_binding_id, sign_binding, verify_binding
from qid.crypto import generate_dev_keypair


def test_verify_binding_rejects_created_at_wrong_type() -> None:
    kp = generate_dev_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="dgb1qxyz",
        policy="ml-dsa",
        ml_dsa_pub_b64u="AAA",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )
    env = sign_binding(payload, kp)

    bad = dict(env)
    bad_payload = dict(payload)
    bad_payload["created_at"] = "nope"  # type: ignore[typeddict-item]
    bad["payload"] = bad_payload  # type: ignore[assignment]

    assert not verify_binding(bad, kp, expected_domain="example.com", now=200)


def test_verify_binding_rejects_expires_at_wrong_type() -> None:
    kp = generate_dev_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="dgb1qxyz",
        policy="ml-dsa",
        ml_dsa_pub_b64u="AAA",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=500,
    )
    env = sign_binding(payload, kp)

    bad = dict(env)
    bad_payload = dict(payload)
    bad_payload["expires_at"] = "nope"  # type: ignore[typeddict-item]
    bad["payload"] = bad_payload  # type: ignore[assignment]

    assert not verify_binding(bad, kp, expected_domain="example.com", now=200)


def test_verify_binding_rejects_expired_binding() -> None:
    kp = generate_dev_keypair()
    payload = build_binding_payload(
        domain="example.com",
        address="dgb1qxyz",
        policy="ml-dsa",
        ml_dsa_pub_b64u="AAA",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=150,
    )

    # craft a valid-looking envelope but verification should fail due to expiry
    env = sign_binding(payload, kp)
    assert not verify_binding(env, kp, expected_domain="example.com", now=200)
