import os
import pytest

import qid.pqc_backends as pb


def test_enforce_hybrid_backend_selected_calls_import(monkeypatch) -> None:
    # Cover enforce_no_silent_fallback_for_alg for HYBRID_ALGO (line ~104).
    os.environ["QID_PQC_BACKEND"] = "liboqs"

    class FakeOQS:
        class Signature:  # pragma: no cover
            pass

    monkeypatch.setattr(pb, "_import_oqs", lambda: FakeOQS())
    pb.enforce_no_silent_fallback_for_alg(pb.HYBRID_ALGO)


def test_validate_oqs_module_rejects_missing_signature() -> None:
    # Cover _validate_oqs_module error path (lines ~71-72).
    with pytest.raises(pb.PQCBackendError):
        pb._validate_oqs_module(object())  # type: ignore[attr-defined]
