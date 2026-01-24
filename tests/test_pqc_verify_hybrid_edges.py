from __future__ import annotations

import pytest
import qid.pqc_verify as pv
import qid.pqc_backends as pb


def _binding_env(policy: str, ml: str = "AA", fa: str = "AA"):
    return {"payload": {"policy": policy, "pqc_pubkeys": {"ml_dsa": ml, "falcon": fa}}}


def test_verify_hybrid_true_when_both_verifies_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    monkeypatch.setattr(pv, "liboqs_verify", lambda *a, **k: True)

    ok = pv.verify_pqc_login(
        login_payload={
            "pqc_alg": pb.HYBRID_ALGO,
            "pqc_sig_ml_dsa": "AA",
            "pqc_sig_falcon": "AA",
        },
        binding_env=_binding_env("hybrid"),
    )
    assert ok is True
