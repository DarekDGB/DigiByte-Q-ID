import pytest
import qid.pqc_backends as pb


def test_import_oqs_hits_backend_not_liboqs_branch(monkeypatch):
    monkeypatch.setenv("QID_PQC_BACKEND", "not-liboqs")

    # CRITICAL: avoid earlier exit
    class Dummy:
        Signature = lambda *a, **k: None

    monkeypatch.setattr(pb, "oqs", Dummy(), raising=False)

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()


def test_liboqs_sign_hits_line_165(monkeypatch):
    # resolver must succeed
    monkeypatch.setattr(pb, "_oqs_alg_for", lambda alg: "X")

    # prevent enforce from exiting early
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    # prevent import crash
    class Dummy:
        Signature = lambda *a, **k: None

    monkeypatch.setattr(pb, "_import_oqs", lambda: Dummy())
    monkeypatch.setattr(pb, "_validate_oqs_module", lambda x: None)

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign("unexpected", b"m", b"k")
