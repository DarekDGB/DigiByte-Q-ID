from __future__ import annotations

import os

import pytest

import qid.pqc_backends as pb


def test_enforce_no_silent_fallback_all_paths() -> None:
    old_backend = os.environ.get("QID_PQC_BACKEND")
    old_oqs = pb.oqs

    try:
        os.environ.pop("QID_PQC_BACKEND", None)
        pb.oqs = pb._OQS_UNSET

        # if qid_alg == DEV_ALGO: return
        assert pb.enforce_no_silent_fallback_for_alg(pb.DEV_ALGO) is None

        # unsupported alg + backend None -> return
        assert pb.enforce_no_silent_fallback_for_alg("not-supported") is None

        # supported alg + backend None -> return
        assert pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO) is None

        # unsupported alg + backend selected -> ValueError
        os.environ["QID_PQC_BACKEND"] = "liboqs"
        with pytest.raises(ValueError, match="Unsupported algorithm for liboqs"):
            pb.enforce_no_silent_fallback_for_alg("not-supported")

    finally:
        if old_backend is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old_backend
        pb.oqs = old_oqs
