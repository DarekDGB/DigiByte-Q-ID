from __future__ import annotations

import pytest

from qid.crypto import DEV_ALGO, generate_dev_keypair, generate_keypair
from qid.integration.adamantine import (
    QIDServiceConfig,
    build_adamantine_qid_evidence_v2,
    build_qid_login_uri,
    prepare_signed_login_response,
    verify_adamantine_qid_evidence,
    verify_signed_login_response_server,
)
from qid.protocol import (
    build_login_request_payload,
    build_login_response_payload,
    login,
)


def _service() -> QIDServiceConfig:
    return QIDServiceConfig(
        service_id="example.com",
        callback_url="https://example.com/qid",
    )


def test_prepare_signed_login_response_rejects_bad_now_and_ttl() -> None:
    service = _service()
    login_uri = build_qid_login_uri(service, "nonce-1")
    keypair = generate_dev_keypair()

    with pytest.raises(ValueError, match="now must be a positive int"):
        prepare_signed_login_response(
            service=service,
            login_uri=login_uri,
            address="dgb1qabc",
            keypair=keypair,
            now=0,
        )

    with pytest.raises(ValueError, match="ttl_seconds must be a positive int"):
        prepare_signed_login_response(
            service=service,
            login_uri=login_uri,
            address="dgb1qabc",
            keypair=keypair,
            now=100,
            ttl_seconds=0,
        )


def test_verify_signed_login_response_server_rejects_unparseable_uri() -> None:
    keypair = generate_dev_keypair()

    assert not verify_signed_login_response_server(
        service=_service(),
        login_uri="not-a-qid-uri",
        response_payload={},
        signature="sig",
        keypair=keypair,
    )


def test_build_adamantine_qid_evidence_v2_happy_path_and_hybrid_container() -> None:
    service = _service()
    keypair = generate_dev_keypair()
    login_uri = build_qid_login_uri(service, "nonce-v2")

    response_payload, signature = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address="dgb1qv2subject",
        keypair=keypair,
        now=1000,
        ttl_seconds=60,
    )

    evidence = build_adamantine_qid_evidence_v2(
        login_uri=login_uri,
        response_payload=response_payload,
        signature=signature,
        hybrid_container_b64="AAEC",
    )

    assert evidence["v"] == "2"
    assert evidence["kind"] == "qid_login_v2"
    assert evidence["subject"] == "dgb1qv2subject"
    assert evidence["proof_hash"]
    assert evidence["hybrid_container_b64"] == "AAEC"

    assert verify_adamantine_qid_evidence(
        service=service,
        evidence=evidence,
        keypair=keypair,
    ) is True


@pytest.mark.parametrize(
    ("response_payload", "expected_error", "expected_message"),
    [
        (
            {"issued_at": 1, "expires_at": 2},
            TypeError,
            "response_payload.address must be a non-empty string",
        ),
        (
            {"address": "dgb1", "issued_at": "1", "expires_at": 2},
            TypeError,
            "response_payload.issued_at/expires_at must be int",
        ),
        (
            {"address": "dgb1", "issued_at": 0, "expires_at": 2},
            ValueError,
            "response_payload.issued_at/expires_at must be positive",
        ),
        (
            {"address": "dgb1", "issued_at": 5, "expires_at": 5},
            ValueError,
            "response_payload.expires_at must be greater than issued_at",
        ),
    ],
)
def test_build_adamantine_qid_evidence_v2_validation_guards(
    response_payload: dict[str, object],
    expected_error: type[Exception],
    expected_message: str,
) -> None:
    with pytest.raises(expected_error, match=expected_message):
        build_adamantine_qid_evidence_v2(
            login_uri="qid://login?d=x",
            response_payload=response_payload,
            signature="sig",
        )


@pytest.mark.parametrize(
    "evidence",
    [
        {
            "v": "2",
            "kind": "qid_login_v2",
            "login_uri": "qid://login?d=x",
            "response_payload": {"address": "dgb1", "issued_at": 1, "expires_at": 2},
            "signature": "sig",
            "proof_hash": "abc",
        },
        {
            "v": "2",
            "kind": "qid_login_v2",
            "login_uri": "qid://login?d=x",
            "response_payload": {"address": "dgb1", "issued_at": 1, "expires_at": 2},
            "signature": "sig",
            "subject": "dgb1",
        },
        {
            "v": "2",
            "kind": "qid_login_v2",
            "login_uri": "qid://login?d=x",
            "response_payload": {"address": "dgb1", "issued_at": 1, "expires_at": 2},
            "signature": "sig",
            "subject": "other",
            "proof_hash": "abc",
        },
        {
            "v": "2",
            "kind": "qid_login_v2",
            "login_uri": "qid://login?d=x",
            "response_payload": {"address": "dgb1", "issued_at": "1", "expires_at": 2},
            "signature": "sig",
            "subject": "dgb1",
            "proof_hash": "abc",
        },
        {
            "v": "2",
            "kind": "qid_login_v2",
            "login_uri": "qid://login?d=x",
            "response_payload": {"address": "dgb1", "issued_at": 5, "expires_at": 5},
            "signature": "sig",
            "subject": "dgb1",
            "proof_hash": "abc",
        },
        {
            "v": "2",
            "kind": "qid_login_v2",
            "login_uri": "qid://login?d=x",
            "response_payload": {"address": "dgb1", "issued_at": 1, "expires_at": 2},
            "signature": "sig",
            "subject": "dgb1",
            "proof_hash": "wrong",
        },
    ],
)
def test_verify_adamantine_qid_evidence_v2_fail_closed_cases(
    evidence: dict[str, object],
) -> None:
    assert verify_adamantine_qid_evidence(
        service=_service(),
        evidence=evidence,  # type: ignore[arg-type]
        keypair=generate_dev_keypair(),
    ) is False


def test_build_login_response_payload_session_window_validation() -> None:
    req = build_login_request_payload(
        service_id="svc",
        nonce="n",
        callback_url="https://cb",
    )

    with pytest.raises(ValueError, match="issued_at/expires_at must be int"):
        build_login_response_payload(
            req,
            address="A",
            pubkey="P",
            issued_at=1,
            expires_at=None,  # type: ignore[arg-type]
        )

    with pytest.raises(ValueError, match="issued_at/expires_at must be positive"):
        build_login_response_payload(
            req,
            address="A",
            pubkey="P",
            issued_at=0,
            expires_at=5,
        )

    with pytest.raises(ValueError, match="expires_at must be greater than issued_at"):
        build_login_response_payload(
            req,
            address="A",
            pubkey="P",
            issued_at=5,
            expires_at=5,
        )


def test_login_happy_path_executes_wrapper_lines() -> None:
    keypair = generate_keypair(DEV_ALGO)

    msg = login(
        "svc",
        "https://cb",
        "n1",
        address="A",
        pubkey=keypair.public_key,
        keypair=keypair,
        key_id="kid-1",
        version="7",
    )

    assert msg.payload["type"] == "login_response"
    assert msg.payload["service_id"] == "svc"
    assert msg.payload["nonce"] == "n1"
    assert msg.payload["key_id"] == "kid-1"
    assert msg.payload["version"] == "7"
