from qid.crypto import generate_dev_keypair
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

    # Service builds login URI
    login_uri = build_qid_login_uri(service, nonce)

    # Wallet side
    keypair = generate_dev_keypair()
    address = "dgb1qxyz123example"

    response_payload, signature = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address=address,
        keypair=keypair,
        key_id="primary",
    )

    # Server verifies
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


def test_adamantine_login_rejects_wrong_service() -> None:
    service = QIDServiceConfig(
        service_id="example.com",
        callback_url="https://example.com/qid",
    )
    other_service = QIDServiceConfig(
        service_id="evil.com",
        callback_url="https://evil.com/qid",
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

    # Wrong service config must fail verification
    ok = verify_signed_login_response_server(
        service=other_service,
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


def test_adamantine_qid_evidence_fail_closed_on_tamper() -> None:
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

    # Tamper response payload (nonce)
    tampered = dict(evidence)
    rp = dict(tampered["response_payload"])
    rp["nonce"] = f'{rp["nonce"]}x'
    tampered["response_payload"] = rp

    assert not verify_adamantine_qid_evidence(
        service=service,
        evidence=tampered,
        keypair=keypair,
    )

    # Tamper signature
    tampered2 = dict(evidence)
    sig = tampered2["signature"]
    tampered2["signature"] = (sig[:-1] + ("A" if sig[-1] != "A" else "B")) if sig else "A"

    assert not verify_adamantine_qid_evidence(
        service=service,
        evidence=tampered2,
        keypair=keypair,
    )


def test_adamantine_qid_evidence_rejects_wrong_types() -> None:
    service = QIDServiceConfig(
        service_id="example.com",
        callback_url="https://example.com/qid",
    )
    keypair = generate_dev_keypair()

    assert not verify_adamantine_qid_evidence(
        service=service,
        evidence={
            "v": "1",
            "kind": "qid_login_v1",
            "login_uri": 123,  # type: ignore[typeddict-item]
            "response_payload": {},
            "signature": "x",
        },  # type: ignore[arg-type]
        keypair=keypair,
    )

    assert not verify_adamantine_qid_evidence(
        service=service,
        evidence={
            "v": "1",
            "kind": "qid_login_v1",
            "login_uri": "qid://x",
            "response_payload": "nope",  # type: ignore[typeddict-item]
            "signature": "x",
        },  # type: ignore[arg-type]
        keypair=keypair,
    )

    assert not verify_adamantine_qid_evidence(
        service=service,
        evidence={
            "v": "1",
            "kind": "qid_login_v1",
            "login_uri": "qid://x",
            "response_payload": {},
            "signature": "",  # empty signature
        },
        keypair=keypair,
    )

    assert not verify_adamantine_qid_evidence(
        service=service,
        evidence={
            "v": "2",  # wrong version
            "kind": "qid_login_v1",
            "login_uri": "qid://x",
            "response_payload": {},
            "signature": "x",
        },
        keypair=keypair,
    )

    assert not verify_adamantine_qid_evidence(
        service=service,
        evidence={
            "v": "1",
            "kind": "other",  # wrong kind
            "login_uri": "qid://x",
            "response_payload": {},
            "signature": "x",
        },
        keypair=keypair,
    )
