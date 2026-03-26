import pytest
import qid.pqc_backends as pb


def test_import_oqs_backend_not_liboqs_branch(monkeypatch):
    """
    Covers:
    if backend != "liboqs": raise PQCBackendError(...)
    """

    monkeypatch.setenv("QID_PQC_BACKEND", "not-liboqs")

    # prevent early oqs None exit
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()


def test_import_oqs_none_return_branch(monkeypatch):
    """
    Covers:
    if real_oqs is None:
    """

    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)

    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "oqs":
            return None
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()


def test_liboqs_sign_force_final_failure_branch(monkeypatch):
    """
    Covers:
    final: raise PQCBackendError("liboqs signing failed")
    """

    # IMPORTANT: backend must be None
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)

    # Force resolver to SUCCEED (so we skip ValueError path)
    monkeypatch.setattr(pb, "_oqs_alg_for", lambda alg: "X")

    # Make enforce_no_silent_fallback a no-op
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    # Valid oqs module
    class FakeOQS:
        class Signature:
            def __init__(self, *a, **k):
                pass

    monkeypatch.setattr(pb, "_import_oqs", lambda: FakeOQS)
    monkeypatch.setattr(pb, "_validate_oqs_module", lambda mod: None)

    # Force NOT ML_DSA / FALCON path
    monkeypatch.setattr(pb, "ML_DSA_ALGO", "ml")
    monkeypatch.setattr(pb, "FALCON_ALGO", "falcon")

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign("other", b"m", b"k")
