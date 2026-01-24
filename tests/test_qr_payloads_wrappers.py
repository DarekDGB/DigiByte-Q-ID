from __future__ import annotations

import pytest
import qid.qr_payloads as qp


def test_build_qr_payload_delegates_to_encode_login_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qp, "encode_login_request", lambda payload: "qid://login?d=TEST")
    assert qp.build_qr_payload({"x": 1}) == "qid://login?d=TEST"


def test_parse_qr_payload_delegates_to_decode_login_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qp, "decode_login_request", lambda uri: {"ok": True, "uri": uri})
    out = qp.parse_qr_payload("qid://login?d=ABC")
    assert out["ok"] is True
    assert out["uri"] == "qid://login?d=ABC"


def test_encode_login_request_uri_is_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qp, "encode_login_request", lambda payload: "qid://login?d=WRAP")
    assert qp.encode_login_request_uri({"x": 2}) == "qid://login?d=WRAP"


def test_decode_login_request_uri_is_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qp, "decode_login_request", lambda uri: {"wrap": True})
    assert qp.decode_login_request_uri("qid://login?d=XYZ") == {"wrap": True}
