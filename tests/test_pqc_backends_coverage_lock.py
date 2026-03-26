import pytest
import types

import qid.pqc_backends as pb


# ---- line ~94 (invalid Signature path) ----
def test_validate_oqs_module_missing_signature():
    class Bad:
        pass

    with pytest.raises(pb.PQCBackendError):
        pb._validate_oqs_module(Bad())


# ---- lines 108–110 (backend != liboqs path) ----
def test_import_oqs_wrong_backend_branch(monkeypatch):
    monkeypatch.setenv("QID_PQC_BACKEND", "wrong")

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()


# ---- line 165 (resolver_ok False path in sign) ----
def test_liboqs_sign_resolver_false_branch(monkeypatch):
    monkeypatch.setattr(pb, "_oqs_alg_for", lambda x: (_ for _ in ()).throw(ValueError()))

    with pytest.raises(ValueError):
        pb.liboqs_sign("bad-alg", b"m", b"k")


# ---- lines 177–178 (verify ValueError path AFTER resolver) ----
def test_liboqs_verify_resolver_valueerror(monkeypatch):
    monkeypatch.setattr(pb, "_oqs_alg_for", lambda x: (_ for _ in ()).throw(ValueError()))

    with pytest.raises(ValueError):
        pb.liboqs_verify(pb.ML_DSA_ALGO, b"m", b"s", b"p")


# ---- FORCE branch where oqs import returns None (rare path) ----
def test_import_oqs_none_return(monkeypatch):
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    def fake_import(*a, **k):
        return None

    monkeypatch.setattr("builtins.__import__", fake_import)

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()
