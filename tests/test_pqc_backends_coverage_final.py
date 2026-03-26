import types
import pytest

import qid.pqc_backends as pb


# --- _import_oqs branches ---


def test_import_oqs_none_backend(monkeypatch):
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", None)

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()


def test_import_oqs_wrong_backend(monkeypatch):
    monkeypatch.setenv("QID_PQC_BACKEND", "something-else")

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()


# --- _validate_oqs_module ---


def test_validate_oqs_module_invalid():
    with pytest.raises(pb.PQCBackendError):
        pb._validate_oqs_module(object())


# --- liboqs_sign resolver branch ---


def test_liboqs_sign_resolver_valueerror(monkeypatch):
    monkeypatch.setattr(pb, "_oqs_alg_for", lambda x: (_ for _ in ()).throw(ValueError()))

    with pytest.raises(ValueError):
        pb.liboqs_sign("bad", b"m", b"k")


# --- liboqs_verify valueerror path ---


def test_liboqs_verify_invalid_alg():
    with pytest.raises(ValueError):
        pb.liboqs_verify("invalid", b"m", b"s", b"p")
