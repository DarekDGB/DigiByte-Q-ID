from qid.crypto import generate_dev_keypair
from qid.integration.adamantine import (
    QIDServiceConfig,
    build_qid_login_uri,
    prepare_signed_login_response,
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
