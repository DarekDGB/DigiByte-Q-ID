import pytest
import qid.pqc_backends as pb


def test_import_oqs_backend_not_liboqs_hits_branch(monkeypatch):
    monkeypatch.setenv("QID_PQC_BACKEND", "not-liboqs")

    # force correct path
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()


def test_liboqs_sign_hits_unexpected_alg_branch(monkeypatch):
    # force resolver success
    monkeypatch.setattr(pb, "_oqs_alg_for", lambda alg: "X")

    # prevent early failures
    class Dummy:
        Signature = lambda *a, **k: None

    monkeypatch.setattr(pb, "_import_oqs", lambda: Dummy())
    monkeypatch.setattr(pb, "_validate_oqs_module", lambda x: None)

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign("unexpected", b"m", b"k")
