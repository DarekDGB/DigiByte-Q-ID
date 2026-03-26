import pytest
import qid.pqc_backends as pb


def test_import_oqs_non_liboqs_backend(monkeypatch):
    monkeypatch.setenv("QID_PQC_BACKEND", "something-else")

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()


def test_liboqs_sign_unexpected_alg_with_resolver(monkeypatch):
    monkeypatch.setattr(pb, "_oqs_alg_for", lambda x: "X")

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign("unexpected", b"m", b"k")
