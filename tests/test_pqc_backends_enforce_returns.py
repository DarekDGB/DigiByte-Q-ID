import qid.pqc_backends as pb


def test_enforce_no_silent_fallback_unsupported_alg_returns_when_backend_none(monkeypatch):
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)

    result = pb.enforce_no_silent_fallback_for_alg("not-supported")

    assert result is None


def test_enforce_no_silent_fallback_supported_alg_returns_when_backend_none(monkeypatch):
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)

    result = pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)

    assert result is None
