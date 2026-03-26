from __future__ import annotations

import pytest

import qid.pqc_backends as pb


def test_enforce_no_silent_fallback_hits_raise_block(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    with pytest.raises(ValueError, match="Unsupported algorithm for liboqs"):
        pb.enforce_no_silent_fallback_for_alg("not-supported")


def test_liboqs_sign_no_backend_generic_exception_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)

    monkeypatch.setattr(pb, "_import_oqs", lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(RuntimeError, match="boom"):
        pb.liboqs_sign(pb.ML_DSA_ALGO, b"msg", b"priv")
