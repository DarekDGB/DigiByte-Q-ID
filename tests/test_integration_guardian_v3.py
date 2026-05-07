import pytest

from qid.crypto import generate_dev_keypair
from qid.integration.adamantine import QIDServiceConfig, build_qid_login_uri, prepare_signed_login_response
from qid.integration.guardian import GuardianServiceConfig
from qid.integration.guardian_v3 import (
    _derived_request_id,
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


def _valid_request(**kwargs):
    gservice, login_uri, response_payload = _make_login()
    return build_guardian_v3_qid_auth_request(
        service=gservice,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_verified=True,
        **kwargs,
    )


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


def test_build_guardian_v3_qid_auth_request_supports_none_signals_and_omitted_optional_keys() -> None:
    gservice, login_uri, response_payload = _make_login()
    response_payload = dict(response_payload)
    response_payload.pop("key_id")
    response_payload.pop("require")

    request = build_guardian_v3_qid_auth_request(
        service=gservice,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_verified=True,
        extra_signals=None,
    )

    assert request["extra_signals"] == {}
    assert "key_id" not in request["auth_ctx"]
    assert "require" not in request["auth_ctx"]
    assert verify_guardian_v3_qid_auth_request(request)


def test_build_guardian_v3_qid_auth_request_optional_fields_and_explicit_request_id() -> None:
    gservice, login_uri, response_payload = _make_login()
    response_payload = dict(response_payload)
    response_payload["require"] = "dual-proof"
    response_payload["issued_at"] = 100
    response_payload["expires_at"] = 200

    request = build_guardian_v3_qid_auth_request(
        service=gservice,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_verified=True,
        binding_verified=True,
        extra_signals={
            "trusted_device": False,
            "device_mismatch": True,
            "device_fingerprint": "fp1",
            "geo_ip": "GB",
            "session": "s1",
        },
        request_id="rid-123",
    )

    assert request["request_id"] == "rid-123"
    assert request["auth_ctx"]["binding_verified"] is True
    assert request["auth_ctx"]["require"] == "dual-proof"
    assert request["auth_ctx"]["issued_at"] == 100
    assert request["auth_ctx"]["expires_at"] == 200
    assert verify_guardian_v3_qid_auth_request(request)


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
    assert req1["request_id"] == _derived_request_id(req1["auth_ctx"], req1["extra_signals"])


@pytest.mark.parametrize(
    "mutator, expected_message",
    [
        (lambda a: a.update(login_uri=""), "login_uri must be a non-empty string"),
        (lambda a: a.update(response_payload=[]), "response_payload must be a dict"),
        (lambda a: a.update(qid_verified="yes"), "qid_verified must be a bool"),
        (lambda a: a.update(binding_verified="yes"), "binding_verified must be a bool when provided"),
        (lambda a: a.update(request_id="   "), "request_id must be a non-empty string when provided"),
    ],
)
def test_build_guardian_v3_qid_auth_request_top_level_type_guards(mutator, expected_message) -> None:
    gservice, login_uri, response_payload = _make_login()
    args = {
        "service": gservice,
        "login_uri": login_uri,
        "response_payload": response_payload,
        "qid_verified": True,
    }
    mutator(args)
    with pytest.raises(TypeError, match=expected_message):
        build_guardian_v3_qid_auth_request(**args)


@pytest.mark.parametrize(
    "service_id, callback_url, expected_message",
    [
        ("wrong.example", "https://example.com/qid", "login_uri service_id does not match expected service"),
        ("example.com", "https://wrong.example/qid", "login_uri callback_url does not match expected service"),
    ],
)
def test_build_guardian_v3_qid_auth_request_login_uri_must_match_expected_service(service_id, callback_url, expected_message) -> None:
    gservice, login_uri, response_payload = _make_login()
    bad_service = GuardianServiceConfig(service_id=service_id, callback_url=callback_url)
    with pytest.raises(TypeError, match=expected_message):
        build_guardian_v3_qid_auth_request(
            service=bad_service,
            login_uri=login_uri,
            response_payload=response_payload,
            qid_verified=True,
        )


@pytest.mark.parametrize(
    "field, value, expected_message",
    [
        ("service_id", None, "response_payload.service_id must be a non-empty string"),
        ("service_id", "", "response_payload.service_id must be a non-empty string"),
        ("nonce", None, "response_payload.nonce must be a non-empty string"),
        ("nonce", "", "response_payload.nonce must be a non-empty string"),
        ("address", None, "response_payload.address must be a non-empty string"),
        ("address", "", "response_payload.address must be a non-empty string"),
        ("pubkey", None, "response_payload.pubkey must be a non-empty string"),
        ("pubkey", "", "response_payload.pubkey must be a non-empty string"),
        ("key_id", "", "response_payload.key_id must be a non-empty string when present"),
        ("key_id", 123, "response_payload.key_id must be a non-empty string when present"),
        ("require", "bad", "response_payload.require must be 'legacy' or 'dual-proof' when present"),
        ("require", 1, "response_payload.require must be 'legacy' or 'dual-proof' when present"),
        ("issued_at", "1", "response_payload.issued_at must be an int when present"),
        ("expires_at", "2", "response_payload.expires_at must be an int when present"),
    ],
)
def test_build_guardian_v3_qid_auth_request_payload_field_guards(field, value, expected_message) -> None:
    gservice, login_uri, response_payload = _make_login()
    bad = dict(response_payload)
    bad[field] = value
    with pytest.raises(TypeError, match=expected_message):
        build_guardian_v3_qid_auth_request(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_verified=True,
        )


def test_build_guardian_v3_qid_auth_request_rejects_half_expiry_pair() -> None:
    gservice, login_uri, response_payload = _make_login()
    bad = dict(response_payload)
    bad["issued_at"] = 100
    with pytest.raises(TypeError, match="response_payload.issued_at/expires_at must be provided together"):
        build_guardian_v3_qid_auth_request(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_verified=True,
        )

    bad = dict(response_payload)
    bad["expires_at"] = 200
    with pytest.raises(TypeError, match="response_payload.issued_at/expires_at must be provided together"):
        build_guardian_v3_qid_auth_request(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_verified=True,
        )


@pytest.mark.parametrize(
    "issued_at, expires_at, expected_message",
    [
        (0, 10, "response_payload.issued_at/expires_at must be positive"),
        (10, 0, "response_payload.issued_at/expires_at must be positive"),
        (5, 5, "response_payload.expires_at must be greater than issued_at"),
        (6, 5, "response_payload.expires_at must be greater than issued_at"),
    ],
)
def test_build_guardian_v3_qid_auth_request_expiry_value_guards(issued_at, expires_at, expected_message) -> None:
    gservice, login_uri, response_payload = _make_login()
    bad = dict(response_payload)
    bad["issued_at"] = issued_at
    bad["expires_at"] = expires_at
    with pytest.raises(ValueError, match=expected_message):
        build_guardian_v3_qid_auth_request(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_verified=True,
        )


@pytest.mark.parametrize(
    "bad_payload, expected_message",
    [
        ({"service_id": "wrong.example"}, "response_payload.service_id mismatch vs expected service"),
        ({"nonce": "zzz"}, "response_payload.nonce mismatch vs login_uri nonce"),
    ],
)
def test_build_guardian_v3_qid_auth_request_rejects_payload_mismatch(bad_payload, expected_message) -> None:
    gservice, login_uri, response_payload = _make_login()
    bad = dict(response_payload)
    bad.update(bad_payload)
    with pytest.raises(TypeError, match=expected_message):
        build_guardian_v3_qid_auth_request(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_verified=True,
        )


@pytest.mark.parametrize(
    "extra_signals, expected_message",
    [
        (["bad"], "extra_signals must be a dict when provided"),
        ({"unknown": "x"}, "extra_signals contains unknown keys"),
        ({"trusted_device": "yes"}, "extra_signals.trusted_device must be a bool"),
        ({"device_mismatch": "yes"}, "extra_signals.device_mismatch must be a bool"),
        ({"session": ""}, "extra_signals.session must be a non-empty string"),
        ({"geo_ip": 123}, "extra_signals.geo_ip must be a non-empty string"),
    ],
)
def test_build_guardian_v3_qid_auth_request_extra_signal_guards(extra_signals, expected_message) -> None:
    gservice, login_uri, response_payload = _make_login()
    with pytest.raises(TypeError, match=expected_message):
        build_guardian_v3_qid_auth_request(
            service=gservice,
            login_uri=login_uri,
            response_payload=response_payload,
            qid_verified=True,
            extra_signals=extra_signals,
        )


def test_verify_guardian_v3_qid_auth_request_rejects_non_dict_and_unknown_top_level() -> None:
    assert not verify_guardian_v3_qid_auth_request([])
    request = _valid_request()
    request["extra"] = "nope"
    assert not verify_guardian_v3_qid_auth_request(request)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda r: r.update(contract_version=2),
        lambda r: r.update(component="wrong"),
        lambda r: r.update(mode="tx"),
        lambda r: r.update(request_id=""),
        lambda r: r.update(wallet_ctx={"balance": 1}),
        lambda r: r.update(tx_ctx={"amount": 1}),
        lambda r: r.update(auth_ctx=[]),
        lambda r: r.update(extra_signals=[]),
        lambda r: r["auth_ctx"].update(unknown=True),
        lambda r: r["auth_ctx"].pop("qid_verified"),
        lambda r: r["auth_ctx"].update(qid_verified="yes"),
        lambda r: r["auth_ctx"].update(service_id=""),
        lambda r: r["auth_ctx"].update(callback_url=""),
        lambda r: r["auth_ctx"].update(nonce=""),
        lambda r: r["auth_ctx"].update(address=""),
        lambda r: r["auth_ctx"].update(pubkey=""),
        lambda r: r["auth_ctx"].update(binding_verified="yes"),
        lambda r: r["auth_ctx"].update(key_id=""),
        lambda r: r["auth_ctx"].update(require="bad"),
        lambda r: r["auth_ctx"].update(issued_at=1),
        lambda r: r["auth_ctx"].update(issued_at="1", expires_at=2),
        lambda r: r["auth_ctx"].update(issued_at=0, expires_at=2),
        lambda r: r["auth_ctx"].update(issued_at=3, expires_at=2),
        lambda r: r["extra_signals"].update(unknown="x"),
        lambda r: r["extra_signals"].update(trusted_device="yes"),
        lambda r: r["extra_signals"].update(session=""),
    ],
)
def test_verify_guardian_v3_qid_auth_request_fail_closed_matrix(mutator) -> None:
    request = _valid_request(extra_signals={"trusted_device": True, "session": "s1"})
    mutator(request)
    assert not verify_guardian_v3_qid_auth_request(request)


def test_verify_guardian_v3_qid_auth_request_accepts_valid_optional_auth_fields() -> None:
    request = _valid_request(
        binding_verified=True,
        extra_signals={"trusted_device": True, "device_mismatch": False, "session": "s1"},
    )
    request["auth_ctx"]["require"] = "legacy"
    request["auth_ctx"]["issued_at"] = 10
    request["auth_ctx"]["expires_at"] = 20
    assert verify_guardian_v3_qid_auth_request(request)
