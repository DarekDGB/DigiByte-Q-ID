from __future__ import annotations

import pytest

import qid.pqc_verify as pv
import qid.pqc_backends as pb


def _binding_env(policy: object = "ml-dsa", ml: object = "AA", fa: object = "AA"):
    return {
        "payload": {
            "policy": policy,
            "pqc_pubkeys": {
                "ml_dsa": ml,
                "falcon": fa,
            },
        }
    }


def test_verify_false_when_no_backend_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": "AA"},
        binding_env=_binding_env(policy="ml-dsa", ml="AA"),
    ) is False


def test_verify_false_on_decode_pubkey_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    monkeypatch.setattr(pv, "liboqs_verify", lambda *args, **kwargs: True)

    # pubkey missing -> _decode_pubkey raises -> verify returns False
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": "AA"},
        binding_env=_binding_env(policy="ml-dsa", ml=""),
    ) is False


def test_verify_false_on_decode_sig_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    monkeypatch.setattr(pv, "liboqs_verify", lambda *args, **kwargs: True)

    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": ""},  # invalid
        binding_env=_binding_env(policy="ml-dsa", ml="AA"),
    ) is False


def test_verify_hybrid_strict_and_false_when_one_side_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    calls = {"n": 0}

    def fake_verify(*args, **kwargs):
        calls["n"] += 1
        # first verify True, second verify False -> AND => False
        return calls["n"] == 1

    monkeypatch.setattr(pv, "liboqs_verify", fake_verify)

    assert pv.verify_pqc_login(
        login_payload={
            "pqc_alg": pb.HYBRID_ALGO,
            "pqc_sig_ml_dsa": "AA",
            "pqc_sig_falcon": "AA",
        },
        binding_env=_binding_env(policy="hybrid", ml="AA", fa="AA"),
    ) is False


def test_verify_fail_closed_when_liboqs_verify_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    def boom(*args, **kwargs):
        raise RuntimeError("x")

    monkeypatch.setattr(pv, "liboqs_verify", boom)

    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": "AA"},
        binding_env=_binding_env(policy="ml-dsa", ml="AA"),
    ) is False


def test_payload_for_pqc_removes_signature_fields() -> None:
    lp = {"a": 1, "pqc_sig": "X", "pqc_sig_ml_dsa": "Y", "pqc_sig_falcon": "Z"}
    d = pv._payload_for_pqc(lp)
    assert d == {"a": 1}
