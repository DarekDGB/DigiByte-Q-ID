import pytest

from qid.crypto import generate_dev_keypair
from qid.integration.adamantine import (
    QIDServiceConfig,
    build_qid_login_uri,
    prepare_signed_login_response,
)
from qid.integration.guardian import (
    GuardianServiceConfig,
    build_guardian_qid_login_event,
    verify_guardian_qid_login_event,
)


def _make_login(service_id: str = "example.com", callback_url: str = "https://example.com/qid"):
    service = QIDServiceConfig(service_id=service_id, callback_url=callback_url)
    gservice = GuardianServiceConfig(service_id=service_id, callback_url=callback_url)

    login_uri = build_qid_login_uri(service, nonce="abc123")
    kp = generate_dev_keypair()

    response_payload, sig = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address="dgb1qxyz123example",
        keypair=kp,
        key_id="primary",
    )
    return service, gservice, login_uri, response_payload, sig, kp


def test_guardian_event_happy_path_build_and_verify() -> None:
    _service, gservice, login_uri, response_payload, sig, _kp = _make_login()

    event = build_guardian_qid_login_event(
        service=gservice,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_signature=sig,
        include_login_uri=True,
    )

    assert verify_guardian_qid_login_event(event)
    assert event["v"] == "1"
    assert event["kind"] == "qid_login_event_v1"
    assert event["service_id"] == "example.com"
    assert event["callback_url"] == "https://example.com/qid"
    assert event["nonce"] == "abc123"
    assert event["address"] == "dgb1qxyz123example"
    assert event["pubkey"] == response_payload["pubkey"]
    assert event["key_id"] == "primary"
    assert event["qid_signature"] == sig
    assert event["login_uri"] == login_uri


def test_guardian_event_build_optional_fields_branches() -> None:
    _service, gservice, login_uri, response_payload, _sig, _kp = _make_login()

    # include_login_uri=False branch + qid_signature=None branch
    event = build_guardian_qid_login_event(
        service=gservice,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_signature=None,
        include_login_uri=False,
    )

    assert verify_guardian_qid_login_event(event)
    assert "login_uri" not in event
    assert "qid_signature" not in event
    assert event["key_id"] == "primary"


def test_guardian_event_build_rejects_bad_inputs() -> None:
    _service, gservice, login_uri, response_payload, sig, _kp = _make_login()

    with pytest.raises(TypeError):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri="",
            response_payload=response_payload,
        )

    with pytest.raises(TypeError):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload="nope",  # type: ignore[arg-type]
        )

    with pytest.raises(TypeError):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=response_payload,
            qid_signature="",
        )

    bad = dict(response_payload)
    bad.pop("address", None)
    with pytest.raises(TypeError):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_signature=sig,
        )

    bad2 = dict(response_payload)
    bad2["key_id"] = ""  # invalid optional field
    with pytest.raises(TypeError):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad2,
            qid_signature=sig,
        )


def test_guardian_event_build_rejects_service_and_callback_mismatch() -> None:
    _service, _gservice, login_uri, response_payload, sig, _kp = _make_login()

    wrong_service = GuardianServiceConfig(service_id="evil.com", callback_url="https://example.com/qid")
    with pytest.raises(TypeError):
        build_guardian_qid_login_event(
            service=wrong_service,
            login_uri=login_uri,
            response_payload=response_payload,
            qid_signature=sig,
        )

    wrong_cb = GuardianServiceConfig(service_id="example.com", callback_url="https://evil.com/qid")
    with pytest.raises(TypeError):
        build_guardian_qid_login_event(
            service=wrong_cb,
            login_uri=login_uri,
            response_payload=response_payload,
            qid_signature=sig,
        )


def test_guardian_event_build_rejects_nonce_mismatch() -> None:
    _service, gservice, login_uri, response_payload, sig, _kp = _make_login()

    bad = dict(response_payload)
    bad["nonce"] = "zzz"
    with pytest.raises(TypeError):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_signature=sig,
        )


def test_guardian_event_verify_fail_closed_matrix() -> None:
    _service, gservice, login_uri, response_payload, sig, _kp = _make_login()

    event = build_guardian_qid_login_event(
        service=gservice,
        login_uri=login_uri,
        response_payload=response_payload,
        qid_signature=sig,
        include_login_uri=True,
    )
    assert verify_guardian_qid_login_event(event)

    e1 = dict(event)
    e1["v"] = "2"
    assert not verify_guardian_qid_login_event(e1)

    e2 = dict(event)
    e2["kind"] = "other"
    assert not verify_guardian_qid_login_event(e2)

    e3 = dict(event)
    e3["extra"] = "nope"
    assert not verify_guardian_qid_login_event(e3)

    e4 = dict(event)
    e4["address"] = ""
    assert not verify_guardian_qid_login_event(e4)

    e5 = dict(event)
    e5["key_id"] = ""
    assert not verify_guardian_qid_login_event(e5)

    e6 = dict(event)
    e6["login_uri"] = ""
    assert not verify_guardian_qid_login_event(e6)

    e7 = dict(event)
    e7["qid_signature"] = ""
    assert not verify_guardian_qid_login_event(e7)

    assert not verify_guardian_qid_login_event("nope")  # type: ignore[arg-type]


# ---- Additional branch coverage tests (guardian.py misses) ----

def test_guardian_build_rejects_nonce_wrong_type_or_empty() -> None:
    _service, gservice, login_uri, response_payload, sig, _kp = _make_login()

    bad = dict(response_payload)
    bad["nonce"] = ""
    with pytest.raises(TypeError, match=r"response_payload\.nonce"):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_signature=sig,
        )


def test_guardian_build_rejects_address_wrong_type_or_empty() -> None:
    _service, gservice, login_uri, response_payload, sig, _kp = _make_login()

    bad = dict(response_payload)
    bad["address"] = ""
    with pytest.raises(TypeError, match=r"response_payload\.address"):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_signature=sig,
        )


def test_guardian_build_rejects_key_id_invalid_branch() -> None:
    _service, gservice, login_uri, response_payload, sig, _kp = _make_login()

    bad = dict(response_payload)
    bad["key_id"] = ""
    with pytest.raises(TypeError, match=r"response_payload\.key_id"):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_signature=sig,
        )


def test_guardian_build_rejects_nonce_mismatch_vs_login_uri_branch() -> None:
    _service, gservice, login_uri, response_payload, sig, _kp = _make_login()

    bad = dict(response_payload)
    bad["nonce"] = "zzz"
    with pytest.raises(TypeError, match="nonce mismatch"):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad,
            qid_signature=sig,
        )


def test_guardian_build_include_login_uri_branch_when_key_id_absent() -> None:
    _service, gservice, login_uri, response_payload, sig, _kp = _make_login()

    no_kid = dict(response_payload)
    no_kid.pop("key_id", None)

    ev = build_guardian_qid_login_event(
        service=gservice,
        login_uri=login_uri,
        response_payload=no_kid,
        qid_signature=sig,
        include_login_uri=True,
    )
    assert "key_id" not in ev
    assert ev["login_uri"] == login_uri
