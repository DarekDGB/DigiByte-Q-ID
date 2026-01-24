from __future__ import annotations

import importlib
import pytest

import qid.pqc_backends as pb


def test_enforce_no_silent_fallback_unknown_backend_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "weird")
    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)


def test_enforce_no_silent_fallback_liboqs_validates_backend_object(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class BadOQS:
        # missing callable Signature
        Signature = None

    monkeypatch.setattr(pb, "_import_oqs", lambda: BadOQS)
    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)


def test_liboqs_sign_typeerror_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class FakeOQS:
        class Signature:
            def __init__(self, *args, **kwargs):
                pass

    monkeypatch.setattr(pb, "_import_oqs", lambda: FakeOQS)
    # validate passes
    monkeypatch.setattr(pb, "_validate_oqs_module", lambda oqs: None)

    mod = importlib.import_module("qid.pqc.pqc_ml_dsa")
    monkeypatch.setattr(mod, "sign_ml_dsa", lambda **kwargs: (_ for _ in ()).throw(TypeError("boom")))

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign(pb.ML_DSA_ALGO, b"msg", b"priv")


def test_liboqs_sign_generic_exception_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class FakeOQS:
        class Signature:
            def __init__(self, *args, **kwargs):
                pass

    monkeypatch.setattr(pb, "_import_oqs", lambda: FakeOQS)
    monkeypatch.setattr(pb, "_validate_oqs_module", lambda oqs: None)

    mod = importlib.import_module("qid.pqc.pqc_falcon")
    monkeypatch.setattr(mod, "sign_falcon", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("x")))

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign(pb.FALCON_ALGO, b"msg", b"priv")


def test_liboqs_verify_fail_closed_on_internal_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class FakeOQS:
        class Signature:
            def __init__(self, *args, **kwargs):
                pass

    monkeypatch.setattr(pb, "_import_oqs", lambda: FakeOQS)
    monkeypatch.setattr(pb, "_validate_oqs_module", lambda oqs: None)

    mod = importlib.import_module("qid.pqc.pqc_ml_dsa")
    monkeypatch.setattr(mod, "verify_ml_dsa", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

    assert pb.liboqs_verify(pb.ML_DSA_ALGO, b"m", b"s", b"p") is False


def test_liboqs_sign_unsupported_alg_raises_valueerror_before_import(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pb, "_import_oqs", lambda: (_ for _ in ()).throw(AssertionError("should not import oqs")))
    with pytest.raises(ValueError):
        pb.liboqs_sign("not-supported", b"m", b"k")


def test_liboqs_verify_unsupported_alg_raises_valueerror_before_import(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pb, "_import_oqs", lambda: (_ for _ in ()).throw(AssertionError("should not import oqs")))
    with pytest.raises(ValueError):
        pb.liboqs_verify("not-supported", b"m", b"s", b"p")
