import pytest

from qid.pqc.pqc_ml_dsa import _set_secret_key, sign_ml_dsa


class _Ctx:
    def __init__(self, obj):
        self._obj = obj

    def __enter__(self):
        return self._obj

    def __exit__(self, exc_type, exc, tb):
        return False


def test_set_secret_key_secret_key_attr_success() -> None:
    class S:
        secret_key = None

    s = S()
    _set_secret_key(s, b"k")
    assert s.secret_key == b"k"


def test_set_secret_key_secret_key_attr_raises_then_sk_raises_then_fails() -> None:
    class S:
        @property
        def secret_key(self):
            return b"x"

        @secret_key.setter
        def secret_key(self, v):
            raise RuntimeError("nope")

        @property
        def _sk(self):
            return b"x"

        @_sk.setter
        def _sk(self, v):
            raise RuntimeError("nope")

    with pytest.raises(RuntimeError, match="Unable to import secret key"):
        _set_secret_key(S(), b"k")


def test_ml_dsa_old_api_import_then_sign_msg_typeerror_then_sign_with_priv() -> None:
    class Signer:
        # force signer.sign(msg, priv) to TypeError so we go import+sign(msg)
        def sign(self, msg, priv=None):
            if priv is not None:
                raise TypeError("no direct priv API")
            raise TypeError("need priv fallback")

        # make secret_key import succeed
        secret_key = None

        # after import, still TypeError on sign(msg) so code falls back to sign(msg, priv)
        def sign(self, msg, priv=None):  # type: ignore[no-redef]
            if priv is None:
                raise TypeError("need priv")
            return b"SIG2"

    class OQS:
        def Signature(self, alg, **kwargs):
            if kwargs:
                raise TypeError("ctor kwargs not supported")  # force old API branch
            return _Ctx(Signer())

    sig = sign_ml_dsa(oqs=OQS(), msg=b"m", priv=b"p", oqs_alg="ML-DSA-44")
    assert sig == b"SIG2"
