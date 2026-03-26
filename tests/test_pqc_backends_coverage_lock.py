import pytest

import qid.pqc_backends as pb


def test_validate_oqs_module_missing_signature():
    class Bad:
        pass

    with pytest.raises(pb.PQCBackendError):
        pb._validate_oqs_module(Bad())


def test_import_oqs_wrong_backend_branch(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("QID_PQC_BACKEND", "wrong")
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()


def test_liboqs_sign_resolver_false_branch(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pb, "_oqs_alg_for", lambda x: (_ for _ in ()).throw(ValueError()))

    with pytest.raises(ValueError):
        pb.liboqs_sign("bad-alg", b"m", b"k")


def test_liboqs_verify_resolver_valueerror(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pb, "_oqs_alg_for", lambda x: (_ for _ in ()).throw(ValueError()))

    with pytest.raises(ValueError):
        pb.liboqs_verify(pb.ML_DSA_ALGO, b"m", b"s", b"p")


def test_import_oqs_none_return(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", None, raising=False)

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()
