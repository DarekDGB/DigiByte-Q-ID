from __future__ import annotations

import pytest

from qid.uri_scheme import decode_registration, decode_uri, encode_registration, encode_uri


def test_encode_decode_roundtrip_generic() -> None:
    payload = {"type": "t", "n": 1, "service_id": "example.com"}
    uri = encode_uri("login", payload)
    got = decode_uri(uri, expected_action="login")
    assert got == payload


def test_encode_decode_roundtrip_register() -> None:
    payload = {"type": "registration", "service_id": "example.com", "nonce": "n1"}
    uri = encode_registration(payload)
    got = decode_registration(uri)
    assert got == payload


def test_decode_rejects_wrong_prefix() -> None:
    with pytest.raises(ValueError):
        decode_uri("http://login?d=abc", expected_action="login")


def test_decode_rejects_missing_query() -> None:
    with pytest.raises(ValueError):
        decode_uri("qid://login", expected_action="login")


def test_decode_rejects_wrong_action() -> None:
    uri = encode_uri("login", {"x": 1})
    with pytest.raises(ValueError):
        decode_uri(uri, expected_action="register")


def test_decode_rejects_missing_d_param() -> None:
    with pytest.raises(ValueError):
        decode_uri("qid://login?x=1", expected_action="login")


def test_decode_rejects_non_json_payload() -> None:
    # create a payload that is valid base64url but not JSON
    # "AA" decodes to b"\x00" which is not JSON
    with pytest.raises(ValueError):
        decode_uri("qid://login?d=AA", expected_action="login")


def test_decode_rejects_non_object_json() -> None:
    # JSON array, not object
    uri = encode_uri("login", {"x": 1})
    # replace d= token with encoded "[]"
    import base64

    token = base64.urlsafe_b64encode(b"[]").decode("ascii").rstrip("=")
    bad = "qid://login?d=" + token
    with pytest.raises(ValueError):
        decode_uri(bad, expected_action="login")
