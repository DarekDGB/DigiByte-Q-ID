import pytest

from qid.anchors import describe_anchor_placeholder
from qid.integration.guardian import guardian_integration_todo
from qid.crypto import (
    DEV_ALGO,
    HYBRID_ALGO,
    ML_DSA_ALGO,
    FALCON_ALGO,
    generate_keypair,
    sign_payload,
    verify_payload,
)
from qid.protocol import (
    build_login_response_payload,
    build_registration_uri,
    parse_registration_uri,
    server_verify_login_response,
    register_identity,
    login,
)
from qid.integration.adamantine import (
    QIDServiceConfig,
    build_qid_login_uri,
    prepare_signed_login_response,
    verify_signed_login_response_server,
)


def test_anchors_placeholder() -> None:
    assert describe_anchor_placeholder() == {"anchor": "todo"}


def test_guardian_placeholder() -> None:
    msg = guardian_integration_todo()
    assert isinstance(msg, str)
    assert "not implemented" in msg.lower()


def test_protocol_placeholders_return_todo() -> None:
    assert register_identity({"x": 1})["status"] == "todo"
    assert login({"x": 1})["status"] == "todo"


def test_build_login_response_rejects_missing_fields() -> None:
    with pytest.raises(ValueError):
        build_login_response_payload(
            request_payload={"type": "login_request"},  # missing service_id/nonce
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
        parse_registration_uri("qid://register")  # no query
    with pytest.raises(ValueError):
        parse_registration_uri("qid://login?d=abc")  # wrong action


def test_registration_parse_rejects_missing_d_or_bad_payload() -> None:
    with pytest.raises(ValueError):
        parse_registration_uri("qid://register?x=1")
    with pytest.raises(ValueError):
        parse_registration_uri("qid://register?d=%%%bad%%%")

    # JSON string "hello" => not an object
    uri = "qid://register?d=ImhlbGxvIg"
    with pytest.raises(ValueError):
        parse_registration_uri(uri)


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


def test_adamantine_verify_returns_false_on_bad_login_uri() -> None:
    service = QIDServiceConfig(service_id="example.com", callback_url="https://example.com/qid")
    keypair = generate_keypair(DEV_ALGO)

    # invalid URI => parse throws inside helper => returns False
    ok = verify_signed_login_response_server(
        service=service,
        login_uri="not-a-qid-uri",
        response_payload={"type": "login_response", "service_id": "example.com", "nonce": "abc123"},
        signature="bad",
        keypair=keypair,
    )
    assert ok is False


def test_crypto_envelope_fail_closed_on_corruption() -> None:
    keypair = generate_keypair(DEV_ALGO)
    payload = {"a": 1}

    sig = sign_payload(payload, keypair)
    assert verify_payload(payload, sig, keypair)

    # Completely invalid signature string => must fail closed (False)
    assert verify_payload(payload, "%%%notbase64%%%", keypair) is False


def test_crypto_alg_mismatch_fails_closed() -> None:
    payload = {"type": "x", "n": 1}
    kp_dev = generate_keypair(DEV_ALGO)
    kp_pqc = generate_keypair(ML_DSA_ALGO)

    sig_dev = sign_payload(payload, kp_dev)
    # verification with different keypair algorithm must fail
    assert verify_payload(payload, sig_dev, kp_pqc) is False


def test_hybrid_requires_both_signatures_strict() -> None:
    payload = {"type": "login_response", "service_id": "example.com", "nonce": "n"}
    kp = generate_keypair(HYBRID_ALGO)
    sig = sign_payload(payload, kp)

    assert verify_payload(payload, sig, kp) is True

    # tamper signature envelope bytes by re-signing with single algo and verifying as hybrid
    kp2 = generate_keypair(FALCON_ALGO)
    sig2 = sign_payload(payload, kp2)
    assert verify_payload(payload, sig2, kp) is False  # alg mismatch => fail closed
