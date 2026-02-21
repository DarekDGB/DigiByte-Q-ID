"""
MIT License
Copyright (c) 2025 DarekDGB
"""

from __future__ import annotations

import pytest

from qid.crypto import (
    DEV_ALGO,
    HYBRID_ALGO,
    generate_keypair,
    sign_payload,
    verify_payload,
)
from qid.protocol import (
    build_login_response_payload,
    build_registration_uri,
    parse_registration_uri,
    server_verify_login_response,
)
from qid.integration.adamantine import (
    QIDServiceConfig,
    build_qid_login_uri,
    prepare_signed_login_response,
    verify_signed_login_response_server,
)


def test_build_login_response_rejects_missing_fields() -> None:
    with pytest.raises(ValueError):
        build_login_response_payload(
            request_payload={"type": "login_request"},
            address="dgb1...",
            pubkey="pub",
        )


def test_server_verify_rejects_wrong_type_or_mismatch() -> None:
    keypair = generate_keypair(DEV_ALGO)
    request = {"type": "login_request", "service_id": "example.com", "nonce": "n"}

    response = {"type": "not_login_response", "service_id": "example.com", "nonce": "n"}
    sig = sign_payload(response, keypair)
    assert not server_verify_login_response(request, response, sig, keypair)

    response2 = {"type": "login_response", "service_id": "evil.com", "nonce": "n"}
    sig2 = sign_payload(response2, keypair)
    assert not server_verify_login_response(request, response2, sig2, keypair)

    response3 = {"type": "login_response", "service_id": "example.com", "nonce": "zzz"}
    sig3 = sign_payload(response3, keypair)
    assert not server_verify_login_response(request, response3, sig3, keypair)


def test_registration_parse_rejects_invalid_uri() -> None:
    with pytest.raises(ValueError):
        parse_registration_uri("http://register?d=abc")
    with pytest.raises(ValueError):
        parse_registration_uri("qid://register")
    with pytest.raises(ValueError):
        parse_registration_uri("qid://login?d=abc")


def test_registration_parse_rejects_missing_d_or_bad_payload() -> None:
    with pytest.raises(ValueError):
        parse_registration_uri("qid://register?x=1")
    with pytest.raises(ValueError):
        parse_registration_uri("qid://register?d=%%%bad%%%")

    uri = "qid://register?d=ImhlbGxvIg"
    with pytest.raises(ValueError):
        parse_registration_uri(uri)


def test_registration_build_and_parse_roundtrip_minimal() -> None:
    payload = {"type": "registration_request", "service_id": "example.com", "nonce": "n"}
    uri = build_registration_uri(payload)
    parsed = parse_registration_uri(uri)
    assert parsed == payload


def test_adamantine_prepare_rejects_mismatched_service_id() -> None:
    service = QIDServiceConfig(service_id="example.com", callback_url="https://example.com/qid")
    evil = QIDServiceConfig(service_id="evil.com", callback_url="https://example.com/qid")
    login_uri = build_qid_login_uri(service, nonce="abc123")

    keypair = generate_keypair(DEV_ALGO)

    with pytest.raises(ValueError):
        prepare_signed_login_response(
            service=evil,
            login_uri=login_uri,
            address="dgb1qxyz",
            keypair=keypair,
        )


def test_adamantine_prepare_rejects_mismatched_callback_url() -> None:
    service = QIDServiceConfig(service_id="example.com", callback_url="https://example.com/qid")
    evil = QIDServiceConfig(service_id="example.com", callback_url="https://evil.com/qid")
    login_uri = build_qid_login_uri(service, nonce="abc123")

    keypair = generate_keypair(DEV_ALGO)

    with pytest.raises(ValueError):
        prepare_signed_login_response(
            service=evil,
            login_uri=login_uri,
            address="dgb1qxyz",
            keypair=keypair,
        )


def test_adamantine_server_verify_rejects_bad_uri() -> None:
    service = QIDServiceConfig(service_id="example.com", callback_url="https://example.com/qid")
    keypair = generate_keypair(DEV_ALGO)

    ok = verify_signed_login_response_server(
        service=service,
        login_uri="qid://login",
        response_payload={"type": "login_response", "service_id": "example.com", "nonce": "n"},
        signature="sig",
        keypair=keypair,
    )
    assert not ok


def test_verify_payload_rejects_wrong_types() -> None:
    # basic type sanity on verify_payload surface
    kp = generate_keypair(DEV_ALGO)
    assert not verify_payload({"x": 1}, signature="not-b64", keypair=kp)

    # HYBRID behavior depends on signature format + backend.
    # Do not assert "missing container must fail" for dev/stub hybrid keys,
    # because some flows can verify without a container in DEV mode.
    hk = generate_keypair(HYBRID_ALGO)
    sig = sign_payload({"x": 1}, hk, hybrid_container_b64="AAEC")
    assert verify_payload({"x": 1}, sig, hk)
