from __future__ import annotations

import pytest

import qid.pqc_backends as pb


def test_enforce_no_silent_fallback_hits_raise_block(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pb, "oqs", None, raising=False)
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg("pqc-ml-dsa")
