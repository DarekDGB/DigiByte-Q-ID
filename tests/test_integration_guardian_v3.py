import pytest

from qid.crypto import generate_dev_keypair
from qid.integration.adamantine import QIDServiceConfig, build_qid_login_uri, prepare_signed_login_response
from qid.integration.guardian import GuardianServiceConfig
from qid.integration.guardian_v3 import (
    build_guardian_v3_qid_auth_request,
    verify_guardian_v3_qid_auth_request,
)


def _make_login(service_id: str = "example.com", callback_url: str = "https://example.com/qid"):
    service = QIDServiceConfig(service_id=service_id, callback_url=callback_url)
    gservice = GuardianServiceConfig(service_id=service_id, callback_url=callback_url)
    login_uri = build_qid_login_uri(service, nonce="abc123")
    kp = generate_dev_keypair()
    response_payload, _sig = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address="dgb1qxyz123example",
        keypair=kp,
        key_id="primary",
    )
    return gservice, login_uri, response_payload


def test_build_guardian_v3_qid_auth_request_happy_path() -> None:
    gservice, login_uri, response_payload = _make_login()

    request = build_guardian_v3_qid_auth_request(
        service=gservice,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_verified=True,
        binding_verified=None,
        extra_signals={"trusted_device": True, "session": "s1", "sentinel_status": "NORMAL"},
    )

    assert verify_guardian_v3_qid_auth_request(request)
    assert request["contract_version"] == 3
    assert request["component"] == "guardian_wallet"
    assert request["mode"] == "qid_auth"
    assert request["wallet_ctx"] == {}
    assert request["tx_ctx"] == {}
    assert request["auth_ctx"]["qid_verified"] is True
    assert request["auth_ctx"]["service_id"] == "example.com"
    assert request["auth_ctx"]["callback_url"] == "https://example.com/qid"
    assert request["auth_ctx"]["nonce"] == "abc123"
    assert request["auth_ctx"]["address"] == "dgb1qxyz123example"
    assert request["auth_ctx"]["key_id"] == "primary"


def test_build_guardian_v3_qid_auth_request_is_deterministic_without_explicit_request_id() -> None:
    gservice, login_uri, response_payload = _make_login()

    req1 = build_guardian_v3_qid_auth_request(
        service=gservice,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_verified=True,
        extra_signals={"trusted_device": True},
    )
    req2 = build_guardian_v3_qid_auth_request(
        service=gservice,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_verified=True,
        extra_signals={"trusted_device": True},
    )

    assert req1["request_id"] == req2["request_id"]
    assert req1 == req2


def test_build_guardian_v3_qid_auth_request_rejects_unknown_signal_and_mismatch() -> None:
    gservice, login_uri, response_payload = _make_login()

    with pytest.raises(TypeError):
        build_guardian_v3_qid_auth_request(
            service=gservice,
            login_uri=login_uri,
            response_payload=response_payload,
            qid_verified=True,
            extra_signals={"unknown": "x"},
        )

    bad = dict(response_payload)
    bad["nonce"] = "zzz"
    with pytest.raises(TypeError):
        build_guardian_v3_qid_auth_request(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_verified=True,
        )


def test_verify_guardian_v3_qid_auth_request_fail_closed_matrix() -> None:
    gservice, login_uri, response_payload = _make_login()
    request = build_guardian_v3_qid_auth_request(
        service=gservice,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_verified=True,
    )
    assert verify_guardian_v3_qid_auth_request(request)

    r1 = dict(request)
    r1["mode"] = "tx"
    assert not verify_guardian_v3_qid_auth_request(r1)

    r2 = dict(request)
    r2["extra"] = "nope"
    assert not verify_guardian_v3_qid_auth_request(r2)

    r3 = dict(request)
    r3["auth_ctx"] = dict(r3["auth_ctx"])
    r3["auth_ctx"]["qid_verified"] = "yes"
    assert not verify_guardian_v3_qid_auth_request(r3)

    r4 = dict(request)
    r4["wallet_ctx"] = {"balance": 1}
    assert not verify_guardian_v3_qid_auth_request(r4)
