from __future__ import annotations

from qid.binding import build_binding_payload, sign_binding
from qid.crypto import generate_keypair
from qid.protocol import (
    REQUIRE_DUAL_PROOF,
    build_login_request_payload,
    build_login_response_payload,
    server_verify_login_response,
    sign_login_response,
)


def _make_binding(kp):
    b_payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )
    return sign_binding(b_payload, kp)


def test_dual_proof_requires_binding_resolver_and_fails_closed_without_pqc() -> None:
    kp = generate_keypair()

    req = build_login_request_payload("example.com", "n1", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF

    b_env = _make_binding(kp)

    def resolver(bid: str):
        return b_env if bid == b_env["binding_id"] else None

    req["_binding_resolver"] = resolver
    req["_now"] = 101

    resp = build_login_response_payload(req, address="ADDR", pubkey="PUB")
    resp["binding_id"] = b_env["binding_id"]
    sig = sign_login_response(resp, kp)

    # In CI (no oqs backend selected), PQC verification MUST fail-closed.
    assert server_verify_login_response(req, resp, sig, kp) is False


def test_dual_proof_missing_resolver_fails_closed() -> None:
    kp = generate_keypair()

    req = build_login_request_payload("example.com", "n2", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF

    b_env = _make_binding(kp)

    resp = build_login_response_payload(req, address="ADDR", pubkey="PUB")
    resp["binding_id"] = b_env["binding_id"]
    sig = sign_login_response(resp, kp)

    assert server_verify_login_response(req, resp, sig, kp) is False


def test_dual_proof_missing_binding_id_fails_closed() -> None:
    kp = generate_keypair()

    req = build_login_request_payload("example.com", "n3", "https://cb")
    req["require"] = REQUIRE_DUAL_PROOF

    b_env = _make_binding(kp)

    def resolver(bid: str):
        return b_env if bid == b_env["binding_id"] else None

    req["_binding_resolver"] = resolver
    req["_now"] = 101

    resp = build_login_response_payload(req, address="ADDR", pubkey="PUB")
    sig = sign_login_response(resp, kp)

    assert server_verify_login_response(req, resp, sig, kp) is False
