import pytest

from qid.crypto import generate_dev_keypair
from qid.integration import adamantine as adam
from qid.integration.adamantine import (
    QIDServiceConfig,
    build_adamantine_qid_evidence,
    build_qid_login_uri,
    prepare_signed_login_response,
    verify_adamantine_qid_evidence,
    verify_signed_login_response_server,
)


def test_adamantine_login_happy_path() -> None:
    service = QIDServiceConfig(
        service_id="example.com",
        callback_url="https://example.com/qid",
    )
    nonce = "abc123"

    login_uri = build_qid_login_uri(service, nonce)

    keypair = generate_dev_keypair()
    address = "dgb1qxyz123example"

    response_payload, signature = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address=address,
        keypair=keypair,
        key_id="primary",
    )

    ok = verify_signed_login_response_server(
        service=service,
        login_uri=login_uri,
        response_payload=response_payload,
        signature=signature,
        keypair=keypair,
    )

    assert ok
    assert response_payload["address"] == address
    assert response_payload["service_id"] == service.service_id
    assert response_payload["nonce"] == nonce


def test_adamantine_login_rejects_wrong_service_id() -> None:
    service = QIDServiceConfig(
        service_id="example.com",
        callback_url="https://example.com/qid",
    )
    other_service = QIDServiceConfig(
        service_id="evil.com",
        callback_url="https://example.com/qid",
    )
    nonce = "abc123"

    login_uri = build_qid_login_uri(service, nonce)

    keypair = generate_dev_keypair()
    address = "dgb1qxyz123example"

    response_payload, signature = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address=address,
        keypair=keypair,
    )

    ok = verify_signed_login_response_server(
        service=other_service,
        login_uri=login_uri,
        response_payload=response_payload,
        signature=signature,
        keypair=keypair,
    )

    assert not ok


def test_adamantine_login_rejects_callback_url_mismatch_branch() -> None:
    # This targets qid/integration/adamantine.py line 115 specifically.
    service = QIDServiceConfig(
        service_id="example.com",
        callback_url="https://example.com/qid",
    )
    other_callback = QIDServiceConfig(
        service_id="example.com",
        callback_url="https://evil.com/qid",
    )

    login_uri = build_qid_login_uri(service, "abc123")

    keypair = generate_dev_keypair()
    response_payload, signature = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address="dgb1qxyz123example",
        keypair=keypair,
        key_id="primary",
    )

    ok = verify_signed_login_response_server(
        service=other_callback,
        login_uri=login_uri,
        response_payload=response_payload,
        signature=signature,
        keypair=keypair,
    )

    assert not ok


def test_adamantine_qid_evidence_happy_path() -> None:
    service = QIDServiceConfig(
        service_id="example.com",
        callback_url="https://example.com/qid",
    )
    nonce = "abc123"
    login_uri = build_qid_login_uri(service, nonce)

    keypair = generate_dev_keypair()
    address = "dgb1qxyz123example"

    response_payload, signature = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address=address,
        keypair=keypair,
        key_id="primary",
    )

    evidence = build_adamantine_qid_evidence(
        login_uri=login_uri,
        response_payload=response_payload,
        signature=signature,
    )

    assert verify_adamantine_qid_evidence(
        service=service,
        evidence=evidence,
        keypair=keypair,
    )


def test_build_adamantine_qid_evidence_includes_hybrid_container() -> None:
    # Targets line 158 (inclusion) and line 148 (type/empty guard for hybrid_container_b64)
    evidence = build_adamantine_qid_evidence(
        login_uri="qid://login?x=y",
        response_payload={"k": "v"},
        signature="sig",
        hybrid_container_b64="AAEC",
    )
    assert evidence["hybrid_container_b64"] == "AAEC"


def test_build_adamantine_qid_evidence_rejects_bad_inputs() -> None:
    # Targets TypeError branches: 140, 142, 144, 148
    with pytest.raises(TypeError):
        build_adamantine_qid_evidence(
            login_uri="",
            response_payload={"k": "v"},
            signature="sig",
        )

    with pytest.raises(TypeError):
        build_adamantine_qid_evidence(
            login_uri="qid://login?x=y",
            response_payload="nope",  # type: ignore[arg-type]
            signature="sig",
        )

    with pytest.raises(TypeError):
        build_adamantine_qid_evidence(
            login_uri="qid://login?x=y",
            response_payload={"k": "v"},
            signature="",
        )

    with pytest.raises(TypeError):
        build_adamantine_qid_evidence(
            login_uri="qid://login?x=y",
            response_payload={"k": "v"},
            signature="sig",
            hybrid_container_b64="",
        )


def test_verify_adamantine_qid_evidence_fail_closed_on_missing_or_wrong_types() -> None:
    # Targets 177 (non-dict) + other fail-closed branches
    service = QIDServiceConfig(service_id="example.com", callback_url="https://example.com/qid")
    keypair = generate_dev_keypair()

    assert not verify_adamantine_qid_evidence(service=service, evidence="nope", keypair=keypair)  # type: ignore[arg-type]
    assert not verify_adamantine_qid_evidence(service=service, evidence={}, keypair=keypair)
    assert not verify_adamantine_qid_evidence(service=service, evidence={"v": "1", "kind": "qid_login_v1"}, keypair=keypair)

    # Targets line 198: hybrid_container_b64 wrong type / empty
    assert not verify_adamantine_qid_evidence(
        service=service,
        evidence={
            "v": "1",
            "kind": "qid_login_v1",
            "login_uri": "qid://x",
            "response_payload": {},
            "signature": "sig",
            "hybrid_container_b64": "",  # invalid (empty)
        },
        keypair=keypair,
    )

    assert not verify_adamantine_qid_evidence(
        service=service,
        evidence={
            "v": "1",
            "kind": "qid_login_v1",
            "login_uri": "qid://x",
            "response_payload": {},
            "signature": "sig",
            "hybrid_container_b64": 123,  # type: ignore[typeddict-item]
        },  # type: ignore[arg-type]
        keypair=keypair,
    )


def test_verify_adamantine_qid_evidence_catches_internal_exception(monkeypatch) -> None:
    # Targets the except Exception: return False branch at 209-210
    service = QIDServiceConfig(service_id="example.com", callback_url="https://example.com/qid")
    keypair = generate_dev_keypair()

    def boom(*args, **kwargs) -> bool:
        raise RuntimeError("boom")

    monkeypatch.setattr(adam, "verify_signed_login_response_server", boom)

    assert not verify_adamantine_qid_evidence(
        service=service,
        evidence={
            "v": "1",
            "kind": "qid_login_v1",
            "login_uri": "qid://x",
            "response_payload": {},
            "signature": "sig",
        },
        keypair=keypair,
    )
