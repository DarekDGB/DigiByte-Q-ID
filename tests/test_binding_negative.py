from __future__ import annotations

import pytest

from qid.binding import (
    build_binding_payload,
    compute_binding_id,
    normalize_domain,
    sign_binding,
    verify_binding,
)
from qid.crypto import DEV_ALGO, generate_keypair


def test_normalize_domain_rejects_empty() -> None:
    with pytest.raises(ValueError):
        normalize_domain("   ")


def test_normalize_domain_rejects_scheme() -> None:
    with pytest.raises(ValueError):
        normalize_domain("https://example.com")


def test_normalize_domain_rejects_path() -> None:
    with pytest.raises(ValueError):
        normalize_domain("example.com/path")


def _valid_binding_env(*, now: int = 100, domain: str = "example.com"):
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain=domain,
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="AA",
        falcon_pub_b64u=None,
        created_at=now,
        expires_at=None,
    )
    env = sign_binding(payload, kp)
    return kp, payload, env


def test_verify_binding_accepts_legacy_signature_field() -> None:
    kp, payload, env = _valid_binding_env(now=100)
    # move signature to legacy field
    env2 = {"binding_id": env["binding_id"], "payload": env["payload"], "signature": env["sig"]}
    assert verify_binding(env2, kp, expected_domain="example.com", now=100) is True


def test_verify_binding_fails_when_missing_signature_fields() -> None:
    kp, payload, env = _valid_binding_env(now=100)
    env2 = {"binding_id": env["binding_id"], "payload": env["payload"]}
    assert verify_binding(env2, kp, expected_domain="example.com", now=100) is False


def test_verify_binding_fails_when_now_wrong_type() -> None:
    kp, payload, env = _valid_binding_env(now=100)
    assert verify_binding(env, kp, expected_domain="example.com", now="100") is False  # type: ignore[arg-type]


def test_verify_binding_fails_when_created_at_in_future() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="AA",
        falcon_pub_b64u=None,
        created_at=200,
        expires_at=None,
    )
    env = sign_binding(payload, kp)
    assert verify_binding(env, kp, expected_domain="example.com", now=100) is False


def test_verify_binding_fails_when_expired() -> None:
    kp = generate_keypair(DEV_ALGO)
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="AA",
        falcon_pub_b64u=None,
        created_at=50,
        expires_at=60,
    )
    env = sign_binding(payload, kp)
    assert verify_binding(env, kp, expected_domain="example.com", now=100) is False


def test_verify_binding_fails_on_binding_id_mismatch() -> None:
    kp, payload, env = _valid_binding_env(now=100)
    bad = dict(env)
    bad["binding_id"] = compute_binding_id({**payload, "address": "OTHER"})  # deterministic wrong
    assert verify_binding(bad, kp, expected_domain="example.com", now=100) is False


def test_verify_binding_fails_on_expected_domain_mismatch() -> None:
    kp, payload, env = _valid_binding_env(now=100, domain="example.com")
    assert verify_binding(env, kp, expected_domain="other.com", now=100) is False
