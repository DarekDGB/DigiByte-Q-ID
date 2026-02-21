import os
from types import SimpleNamespace

import pytest

from qid.pqc import keygen_liboqs


class _SigBase:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def generate_keypair(self):
        return b"PUB"


class _SigExport(_SigBase):
    def export_secret_key(self):
        return b"SK"


class _SigSecretAttr(_SigBase):
    @property
    def secret_key(self):
        return b"SK_ATTR"


class _SigSkAttr(_SigBase):
    def __init__(self):
        self._sk = b"SK__SK"


class _SigNoSecret(_SigBase):
    pass


class _SigBadPub(_SigBase):
    def generate_keypair(self):
        return "NOT_BYTES"  # triggers line 94 / 115


def test_export_secret_key_variants_secret_key_and__sk(monkeypatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    # secret_key attribute path -> hits 62-65
    fake1 = SimpleNamespace(Signature=lambda alg: _SigSecretAttr())
    monkeypatch.setattr(keygen_liboqs, "oqs", fake1, raising=True)
    pub, sec = keygen_liboqs.generate_falcon_keypair("Falcon-512")
    assert pub == b"PUB"
    assert sec == b"SK_ATTR"

    # _sk attribute path -> hits 67-70
    fake2 = SimpleNamespace(Signature=lambda alg: _SigSkAttr())
    monkeypatch.setattr(keygen_liboqs, "oqs", fake2, raising=True)
    pub2, sec2 = keygen_liboqs.generate_falcon_keypair("Falcon-512")
    assert pub2 == b"PUB"
    assert sec2 == b"SK__SK"


def test_export_secret_key_raises_when_no_supported_api(monkeypatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    fake = SimpleNamespace(Signature=lambda alg: _SigNoSecret())
    monkeypatch.setattr(keygen_liboqs, "oqs", fake, raising=True)

    with pytest.raises(keygen_liboqs.PQCBackendError):
        keygen_liboqs.generate_falcon_keypair("Falcon-512")


def test_generate_keypair_must_return_bytes_ml_dsa_and_falcon(monkeypatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    fake = SimpleNamespace(Signature=lambda alg: _SigBadPub())
    monkeypatch.setattr(keygen_liboqs, "oqs", fake, raising=True)

    with pytest.raises(keygen_liboqs.PQCBackendError):
        keygen_liboqs.generate_ml_dsa_keypair("ML-DSA-44")

    with pytest.raises(keygen_liboqs.PQCBackendError):
        keygen_liboqs.generate_falcon_keypair("Falcon-512")
