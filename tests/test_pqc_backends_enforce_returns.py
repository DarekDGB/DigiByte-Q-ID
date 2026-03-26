from __future__ import annotations

import pytest

import qid.pqc_backends as pb


@pytest.fixture(autouse=True)
def _reset_backend_state(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)
    yield
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)


def test_enforce_no_silent_fallback_unsupported_alg_returns_when_backend_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)

    result = pb.enforce_no_silent_fallback_for_alg("not-supported")

    assert result is None


def test_enforce_no_silent_fallback_supported_alg_returns_when_backend_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)

    result = pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)

    assert result is None


def test_enforce_no_silent_fallback_unsupported_alg_raises_when_backend_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    with pytest.raises(ValueError, match="Unsupported algorithm for liboqs"):
        pb.enforce_no_silent_fallback_for_alg("not-supported")
