import builtins
import os

import pytest

import qid.pqc_backends as pb
import qid.pqc_verify as pv


class _FakeSig:
    def __init__(self, *a, **k):
        pass


class _FakeOQSModule:
    Signature = _FakeSig


def test_pqc_backends_import_success_path_via_monkeypatched_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover _import_oqs success path without real oqs installed."""
    old_env = os.environ.get("QID_PQC_BACKEND")
    old_oqs = pb.oqs
    old_import = builtins.__import__
    try:
        os.environ["QID_PQC_BACKEND"] = "liboqs"
        pb.oqs = getattr(pb, "_OQS_UNSET")  # force import path

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "oqs":
                return _FakeOQSModule()
            return old_import(name, globals, locals, fromlist, level)

        builtins.__import__ = fake_import  # type: ignore[assignment]
        pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)  # should not raise
        assert pb.oqs is not getattr(pb, "_OQS_UNSET")
    finally:
        if old_env is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old_env
        pb.oqs = old_oqs
        builtins.__import__ = old_import  # type: ignore[assignment]


def test_pqc_backends_sign_error_branches_are_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    old_env = os.environ.get("QID_PQC_BACKEND")
    old_oqs = pb.oqs
    try:
        os.environ["QID_PQC_BACKEND"] = "liboqs"
        pb.oqs = _FakeOQSModule()

        import qid.pqc.pqc_ml_dsa as ml

        monkeypatch.setattr(ml, "sign_ml_dsa", lambda **k: (_ for _ in ()).throw(TypeError("x")))
        with pytest.raises(pb.PQCBackendError):
            pb.liboqs_sign(pb.ML_DSA_ALGO, b"m", b"s")

        monkeypatch.setattr(ml, "sign_ml_dsa", lambda **k: (_ for _ in ()).throw(RuntimeError("x")))
        with pytest.raises(pb.PQCBackendError):
            pb.liboqs_sign(pb.ML_DSA_ALGO, b"m", b"s")
    finally:
        if old_env is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old_env
        pb.oqs = old_oqs


def test_pqc_backends_verify_fail_closed_on_internal_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    old_env = os.environ.get("QID_PQC_BACKEND")
    old_oqs = pb.oqs
    try:
        os.environ["QID_PQC_BACKEND"] = "liboqs"
        pb.oqs = _FakeOQSModule()

        import qid.pqc.pqc_ml_dsa as ml

        monkeypatch.setattr(ml, "verify_ml_dsa", lambda **k: (_ for _ in ()).throw(RuntimeError("x")))
        assert pb.liboqs_verify(pb.ML_DSA_ALGO, b"m", b"sig", b"pub") is False

        with pytest.raises(ValueError):
            pb.liboqs_verify("not-supported", b"m", b"sig", b"pub")  # type: ignore[arg-type]
    finally:
        if old_env is None:
            os.environ.pop("QID_PQC_BACKEND", None)
        else:
            os.environ["QID_PQC_BACKEND"] = old_env
        pb.oqs = old_oqs


def test_pqc_verify_decode_sig_missing_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hit a few remaining fail-closed branches."""
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    monkeypatch.setattr(pv, "liboqs_verify", lambda *a, **k: True)

    # missing signature field -> False (covers _decode_sig ValueError path)
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pb.ML_DSA_ALGO},
        binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "AA"}}},
    ) is False
