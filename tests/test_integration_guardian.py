import pytest

from qid.crypto import generate_dev_keypair
from qid.integration.adamantine import QIDServiceConfig, build_qid_login_uri, prepare_signed_login_response
from qid.integration.guardian import (
    GuardianServiceConfig,
    build_guardian_qid_login_event,
    verify_guardian_qid_login_event,
)


def test_guardian_event_happy_path_build_and_verify() -> None:
    service = QIDServiceConfig(service_id="example.com", callback_url="https://example.com/qid")
    gservice = GuardianServiceConfig(service_id="example.com", callback_url="https://example.com/qid")

    login_uri = build_qid_login_uri(service, nonce="abc123")

    kp = generate_dev_keypair()
    response_payload, sig = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address="dgb1qxyz123example",
        keypair=kp,
        key_id="primary",
    )

    event = build_guardian_qid_login_event(
        service=gservice,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_signature=sig,
        include_login_uri=True,
    )

    assert verify_guardian_qid_login_event(event)
    assert event["service_id"] == "example.com"
    assert event["callback_url"] == "https://example.com/qid"
    assert event["nonce"] == "abc123"
    assert event["address"] == "dgb1qxyz123example"
    assert event["key_id"] == "primary"
    assert event["qid_signature"] == sig
    assert event["login_uri"] == login_uri


def test_guardian_event_fail_closed_on_wrong_types_and_unexpected_keys() -> None:
    assert not verify_guardian_qid_login_event("nope")  # type: ignore[arg-type]
    assert not verify_guardian_qid_login_event({})

    # unexpected key => deny-by-default
    bad = {
        "v": "1",
        "kind": "qid_login_event_v1",
        "service_id": "example.com",
        "callback_url": "https://example.com/qid",
        "nonce": "n",
        "address": "a",
        "pubkey": "p",
        "extra": "nope",
    }
    assert not verify_guardian_qid_login_event(bad)


def test_guardian_build_rejects_service_or_nonce_mismatch() -> None:
    service = QIDServiceConfig(service_id="example.com", callback_url="https://example.com/qid")
    gservice = GuardianServiceConfig(service_id="example.com", callback_url="https://example.com/qid")

    login_uri = build_qid_login_uri(service, nonce="abc123")

    kp = generate_dev_keypair()
    response_payload, sig = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address="dgb1qxyz123example",
        keypair=kp,
        key_id="primary",
    )

    # tamper nonce => should raise TypeError (fail-closed)
    bad_resp = dict(response_payload)
    bad_resp["nonce"] = "zzz"
    with pytest.raises(TypeError):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad_resp,
            qid_signature=sig,
        )

    # wrong service config => should raise TypeError (fail-closed)
    wrong = GuardianServiceConfig(service_id="evil.com", callback_url="https://example.com/qid")
    with pytest.raises(TypeError):
        build_guardian_qid_login_event(
            service=wrong,
            login_uri=login_uri,
            response_payload=response_payload,
            qid_signature=sig,
        )
