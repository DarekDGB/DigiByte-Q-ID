from qid.crypto import generate_dev_keypair, sign_payload, verify_payload


def test_sign_and_verify_roundtrip() -> None:
    keypair = generate_dev_keypair()
    payload = {
        "type": "login_request",
        "service_id": "example.com",
        "nonce": "abc123",
        "callback_url": "https://example.com/qid",
        "version": "1",
    }

    sig = sign_payload(payload, keypair)
    assert isinstance(sig, str)
    assert sig  # not empty

    assert verify_payload(payload, sig, keypair)


def test_verify_detects_tampering() -> None:
    keypair = generate_dev_keypair()
    payload = {
        "type": "login_request",
        "service_id": "example.com",
        "nonce": "abc123",
        "callback_url": "https://example.com/qid",
        "version": "1",
    }

    sig = sign_payload(payload, keypair)

    # Change the payload → signature must no longer verify
    tampered = dict(payload)
    tampered["nonce"] = "xyz999"

    assert not verify_payload(tampered, sig, keypair)
