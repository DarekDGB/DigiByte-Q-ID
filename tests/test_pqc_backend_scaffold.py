import importlib.util
import os

import pytest

import qid.pqc_backends as pb
from qid.crypto import ML_DSA_ALGO, generate_keypair, sign_payload
from qid.pqc_backends import PQCBackendError


def test_no_backend_selected_does_not_block_signing() -> None:
    os.environ.pop("QID_PQC_BACKEND", None)
    kp = generate_keypair(ML_DSA_ALGO)
    sig = sign_payload({"x": 1}, kp)
    assert isinstance(sig, str) and sig


def test_backend_selected_fails_closed_until_wired() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"
    try:
        kp = generate_keypair(ML_DSA_ALGO)
        has_oqs = importlib.util.find_spec("oqs") is not None

        if os.getenv("QID_PQC_TESTS") == "1" and has_oqs:
            sig = sign_payload({"x": 1}, kp)
            assert isinstance(sig, str) and sig
        else:
            with pytest.raises(PQCBackendError):
                sign_payload({"x": 1}, kp)
    finally:
        os.environ.pop("QID_PQC_BACKEND", None)


def test_import_oqs_failure_path_is_covered(monkeypatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "oqs":
            raise ImportError("no oqs")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()  # type: ignore[attr-defined]


def test_liboqs_not_wired_error_paths_are_covered(monkeypatch) -> None:
    monkeypatch.setattr(pb, "_import_oqs", lambda: object())

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_sign(pb.ML_DSA_ALGO, b"payload", b"priv")  # type: ignore[attr-defined]

    with pytest.raises(pb.PQCBackendError):
        pb.liboqs_verify(pb.FALCON_ALGO, b"payload", b"sig", b"pub")  # type: ignore[attr-defined]
