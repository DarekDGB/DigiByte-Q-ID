import pytest
import qid.pqc_backends as pb


def test_import_oqs_backend_not_liboqs_branch(monkeypatch):
    """
    Covers lines 108–110:
    if backend != "liboqs": raise PQCBackendError(...)
    """

    monkeypatch.setenv("QID_PQC_BACKEND", "something_else")

    # prevent early exit on oqs None
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)

    with pytest.raises(pb.PQCBackendError, match="No real PQC backend selected"):
        pb._import_oqs()


def test_import_oqs_none_return_branch(monkeypatch):
    """
    Covers lines 108–110 (real_oqs is None branch)
    """

    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    # bypass cached oqs
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)

    # force import oqs → None
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "oqs":
            return None
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(pb.PQCBackendError, match="oqs import returned None"):
        pb._import_oqs()


def test_liboqs_sign_final_failure_branch(monkeypatch):
    """
    Covers line 165:
    final raise PQCBackendError("liboqs signing failed")
    """

    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)

    # Force resolver to succeed (so we skip ValueError path)
    monkeypatch.setattr(pb, "_oqs_alg_for", lambda alg: "X")

    # Make sure it reaches final failure
    monkeypatch.setattr(pb, "_import_oqs", lambda: type("M", (), {"Signature": lambda *a, **k: None})())

    # Force both ML + Falcon paths to NOT trigger
    monkeypatch.setattr(pb, "ML_DSA_ALGO", "ml")
    monkeypatch.setattr(pb, "FALCON_ALGO", "falcon")

    with pytest.raises(pb.PQCBackendError, match="liboqs signing failed"):
        pb.liboqs_sign("other", b"m", b"k")
