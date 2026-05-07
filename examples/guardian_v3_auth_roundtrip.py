"""
Example: Q-ID -> Guardian Wallet v3 auth request roundtrip.

This example only builds and validates the Q-ID side request.
It does not import Wallet Guardian directly.
"""

from qid.crypto import generate_dev_keypair
from qid.integration.adamantine import (
    QIDServiceConfig,
    build_qid_login_uri,
    prepare_signed_login_response,
)
from qid.integration.guardian import GuardianServiceConfig
from qid.integration.guardian_v3 import (
    build_guardian_v3_qid_auth_request,
    verify_guardian_v3_qid_auth_request,
)


def main() -> None:
    service = QIDServiceConfig(
        service_id="example.com",
        callback_url="https://example.com/qid",
    )
    guardian_service = GuardianServiceConfig(
        service_id="example.com",
        callback_url="https://example.com/qid",
    )

    login_uri = build_qid_login_uri(service, nonce="abc123")
    keypair = generate_dev_keypair()

    response_payload, _signature = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address="dgb1qexampleaddress0001",
        keypair=keypair,
        key_id="primary",
    )

    request = build_guardian_v3_qid_auth_request(
        service=guardian_service,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_verified=True,
        binding_verified=True,
        extra_signals={
            "trusted_device": True,
            "session": "session-1",
            "sentinel_status": "NORMAL",
        },
    )

    assert verify_guardian_v3_qid_auth_request(request) is True

    print("Guardian Wallet v3 auth request built successfully:")
    print(request)


if __name__ == "__main__":
    main()
