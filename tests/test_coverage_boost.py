from __future__ import annotations

import builtins
import types
import pytest

import qid.crypto as crypto
import qid.pqc_backends as pb
from qid.hybrid_key_container import (
    build_container,
    decode_container,
    encode_container,
    _b64_std_decode,
)

from qid.pqc.pqc_ml_dsa import sign_ml_dsa, verify_ml_dsa
from qid.pqc.pqc_falcon import sign_falcon, verify_falcon


def test_stub_verify_pqc_rejects_bad_prefix() -> None:
    msg = b"m"
    secret = b"s" * 32
    sig = b"wrong:" + b"x" * 64
    assert crypto._stub_verify_pqc(msg, secret, sig, crypto.ML_DSA_ALGO) is False


def test_generate_keypair_rejects_unknown_algorithm() -> None:
    with pytest.raises(ValueError):
        crypto.generate_keypair("not-a-real-alg")  # type: ignore[arg-type]


def test_sign_payload_rejects_unknown_algorithm() -> None:
    kp = crypto.QIDKeyPair(algorithm="nope", public_key="AA", secret_key="AA")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        crypto.sign_payload({"x": 1}, kp)


def test_verify_payload_fail_closed_on_pqc_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = crypto.QIDKeyPair(
        algorithm=crypto.ML_DSA_ALGO,
        public_key=crypto._b64encode(b"p"),
        secret_key=crypto._b64encode(b"s" * 32),
    )
    sig = crypto.sign_payload({"x": 1}, kp)

    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "_import_oqs", lambda: object())
    monkeypatch.setattr(pb, "liboqs_verify", lambda *a, **k: (_ for _ in ()).throw(pb.PQCBackendError("boom")))
    assert crypto.verify_payload({"x": 1}, sig, kp) is False

    monkeypatch.setattr(pb, "liboqs_verify", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert crypto.verify_payload({"x": 1}, sig, kp) is False

    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)


def test_pqc_backends_misc_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "  LiBoQs  ")
    assert pb.selected_backend() == "liboqs"
    assert pb.require_real_pqc() is True

    monkeypatch.setenv("QID_PQC_BACKEND", "weird")
    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)

    with pytest.raises(ValueError):
        pb._oqs_alg_for("not-supported")  # type: ignore[arg-type]

    with pytest.raises(pb.PQCBackendError):
        pb._validate_oqs_module(object())

    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)


def test_import_oqs_failure_path_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "oqs":
            raise ImportError("no oqs")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(pb.PQCBackendError):
        pb._import_oqs()  # type: ignore[attr-defined]


def test_hybrid_container_failure_paths_are_covered() -> None:
    with pytest.raises(ValueError):
        _b64_std_decode("")

    bad = {"kid": "", "alg": "pqc-hybrid-ml-dsa-falcon", "ml_dsa": {}, "falcon": {}, "container_hash": "x"}
    with pytest.raises(ValueError):
        decode_container(bad)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        build_container(1, 2)  # type: ignore[misc]

    with pytest.raises(ValueError):
        build_container(kid="", ml_dsa_public_key="a", falcon_public_key="b")  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        build_container(kid="k", ml_dsa_public_key="", falcon_public_key="")  # type: ignore[arg-type]


def test_pqc_ml_dsa_and_falcon_sign_verify_branches() -> None:
    msg = b"hello"
    priv = b"k" * 10
    pub = b"p"

    class SigOK:
        def __init__(self, alg: str, secret_key: bytes | None = None):
            self.alg = alg
            self.secret_key = secret_key

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def sign(self, m: bytes, sk: bytes | None = None):
            return b"SIG:" + m

        def verify(self, m: bytes, sig: bytes, pk: bytes):
            return sig == b"SIG:" + m and pk == pub

    oqs1 = types.SimpleNamespace(Signature=SigOK)
    assert sign_ml_dsa(oqs=oqs1, msg=msg, priv=priv, oqs_alg="Dilithium2") == b"SIG:" + msg
    assert sign_falcon(oqs=oqs1, msg=msg, priv=priv, oqs_alg="Falcon-512") == b"SIG:" + msg
    assert verify_ml_dsa(oqs=oqs1, msg=msg, sig=b"SIG:" + msg, pub=pub, oqs_alg="Dilithium2") is True
    assert verify_falcon(oqs=oqs1, msg=msg, sig=b"SIG:" + msg, pub=pub, oqs_alg="Falcon-512") is True

    class SigFallback:
        def __init__(self, alg: str, secret_key: bytes | None = None):
            if secret_key is not None:
                raise TypeError("no secret_key kw")
            self.alg = alg
            self._sk = None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def import_secret_key(self, sk: bytes):
            self._sk = sk

        def sign(self, m: bytes):
            return b"OK2:" + m

        def verify(self, m: bytes, sig: bytes, pk: bytes):
            return True

    oqs2 = types.SimpleNamespace(Signature=SigFallback)
    assert sign_ml_dsa(oqs=oqs2, msg=msg, priv=priv, oqs_alg="Dilithium2") == b"OK2:" + msg
    assert sign_falcon(oqs=oqs2, msg=msg, priv=priv, oqs_alg="Falcon-512") == b"OK2:" + msg

    class SigBoom:
        def __init__(self, alg: str, secret_key: bytes | None = None):
            if secret_key is not None:
                raise TypeError("no secret_key kw")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def sign(self, *a, **k):
            raise RuntimeError("boom")

        def verify(self, *a, **k):
            raise RuntimeError("boom")

    oqs3 = types.SimpleNamespace(Signature=SigBoom)
    with pytest.raises(RuntimeError):
        sign_ml_dsa(oqs=oqs3, msg=msg, priv=priv, oqs_alg="Dilithium2")
    with pytest.raises(RuntimeError):
        sign_falcon(oqs=oqs3, msg=msg, priv=priv, oqs_alg="Falcon-512")
    assert verify_ml_dsa(oqs=oqs3, msg=msg, sig=b"x", pub=pub, oqs_alg="Dilithium2") is False
    assert verify_falcon(oqs=oqs3, msg=msg, sig=b"x", pub=pub, oqs_alg="Falcon-512") is False
