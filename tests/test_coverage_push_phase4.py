from __future__ import annotations

import pytest

import qid.crypto as crypto
import qid.pqc.keygen_liboqs as kl
import qid.pqc.pqc_falcon as pf
import qid.pqc.pqc_ml_dsa as pmd
import qid.pqc_sign as ps
from qid.crypto import QIDKeyPair
from qid.hybrid_key_container import build_container, encode_container
from qid.pqc_backends import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO


class _ImportedThenMsgOnlyTypeErrorSigner:
    def __init__(self) -> None:
        self.imported = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    @property
    def secret_key(self) -> bytes:
        return b""

    @secret_key.setter
    def secret_key(self, value: bytes) -> None:
        self.imported = True

    def sign(self, msg: bytes, priv: bytes | None = None) -> bytes:
        if not self.imported:
            raise TypeError("pre-import direct sign unsupported")
        if priv is None:
            raise TypeError("msg-only unsupported after import")
        return b"fallback:" + priv + b":" + msg


class _NoKwFactory:
    def __init__(self, signer_cls):
        self.signer_cls = signer_cls

    def __call__(self, alg: str, secret_key: bytes | None = None):
        if secret_key is not None:
            raise TypeError("ctor kwargs unsupported")
        return self.signer_cls()


class _OQSTypeErrorAfterImport:
    Signature = _NoKwFactory(_ImportedThenMsgOnlyTypeErrorSigner)


class _NoSecretImportSigner:
    pass


class _BadSkSigner:
    _sk = "not-bytes"


def test_export_secret_key_raises_when_private_attr_is_not_bytes() -> None:
    with pytest.raises(kl.PQCBackendError, match="usable secret key export API"):
        kl._export_secret_key(_BadSkSigner())


def test_falcon_sign_typeerror_after_import_falls_back_to_sign_msg_priv() -> None:
    assert pf.sign_falcon(oqs=_OQSTypeErrorAfterImport(), msg=b"m", priv=b"k") == b"fallback:k:m"


def test_ml_dsa_set_secret_key_raises_when_no_supported_import_path_exists() -> None:
    with pytest.raises(RuntimeError, match="Unable to import secret key"):
        pmd._set_secret_key(_NoSecretImportSigner(), b"k")


def test_ml_dsa_sign_typeerror_after_import_falls_back_to_sign_msg_priv() -> None:
    assert pmd.sign_ml_dsa(oqs=_OQSTypeErrorAfterImport(), msg=b"m", priv=b"k") == b"fallback:k:m"


def test_pqc_sign_b64url_decode_round_trip_paths() -> None:
    encoded = ps._b64url_encode(b"abc")
    assert ps._b64url_decode(encoded) == b"abc"


def test_crypto_verify_payload_backend_micro_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(crypto, "selected_backend", lambda: "liboqs", raising=False)
    monkeypatch.setattr(crypto, "enforce_no_silent_fallback_for_alg", lambda alg: None, raising=False)

    kp_single = QIDKeyPair(algorithm=ML_DSA_ALGO, public_key="AA==", secret_key="AA==")
    sig_env_single = crypto._envelope_encode(
        {"v": crypto._SIG_ENVELOPE_VERSION, "alg": ML_DSA_ALGO, "sig": 123}
    )
    assert crypto.verify_payload({"x": 1}, sig_env_single, kp_single) is False

    kp_hybrid = QIDKeyPair(algorithm=HYBRID_ALGO, public_key="AA==", secret_key="AA==")
    container_b64 = encode_container(
        build_container(kid="kid", ml_dsa_public_key="AA==", falcon_public_key="AA==")
    )
    sig_env_missing = crypto._envelope_encode(
        {
            "v": crypto._SIG_ENVELOPE_VERSION,
            "alg": HYBRID_ALGO,
            "sigs": {ML_DSA_ALGO: "AA", FALCON_ALGO: 123},
        }
    )
    assert crypto.verify_payload({"x": 1}, sig_env_missing, kp_hybrid, hybrid_container_b64=container_b64) is False

    monkeypatch.setattr(crypto, "_b64decode", lambda s: (_ for _ in ()).throw(RuntimeError("boom")), raising=False)
    sig_env_boom = crypto._envelope_encode(
        {"v": crypto._SIG_ENVELOPE_VERSION, "alg": ML_DSA_ALGO, "sig": "AA"}
    )
    assert crypto.verify_payload({"x": 1}, sig_env_boom, kp_single) is False
