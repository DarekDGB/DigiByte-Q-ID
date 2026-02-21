import pytest

from qid.pqc.pqc_falcon import sign_falcon, verify_falcon
from qid.pqc.pqc_ml_dsa import sign_ml_dsa, verify_ml_dsa


class _Ctx:
    def __init__(self, signer):
        self._signer = signer

    def __enter__(self):
        return self._signer

    def __exit__(self, exc_type, exc, tb):
        return False


def test_ml_dsa_ctor_kwargs_then_sign_typeerror_fallback() -> None:
    # Hits pqc_ml_dsa lines 46-47 (sign(msg) TypeError -> sign(msg, priv))
    class Signer:
        def sign(self, msg, priv=None):
            if priv is None:
                raise TypeError("need priv")
            return b"SIG"

    class OQS:
        def Signature(self, alg, **kwargs):
            # accept ctor kwargs
            return _Ctx(Signer())

    sig = sign_ml_dsa(oqs=OQS(), msg=b"m", priv=b"p")
    assert sig == b"SIG"


def test_ml_dsa_ctor_kwargs_returns_none_is_fail_closed() -> None:
    # Hits pqc_ml_dsa line 49 (None) and outer cleanup+RuntimeError path (69-70, 71)
    class Signer:
        def sign(self, msg, priv=None):
            return None

    class OQS:
        def Signature(self, alg, **kwargs):
            return _Ctx(Signer())

    with pytest.raises(RuntimeError):
        sign_ml_dsa(oqs=OQS(), msg=b"m", priv=b"p")


def test_ml_dsa_old_api_set_secret_key_exception_paths_then_sign_typeerror_fallback() -> None:
    # Forces ctor kwargs to TypeError so code goes to "older API" branch.
    # Hits _set_secret_key exception/pass paths: 14-18 and 22-26.
    # Also hits sign(msg) TypeError fallback in older API path (60-61).
    class Signer:
        # secret_key assignment fails
        @property
        def secret_key(self):
            return b"x"

        @secret_key.setter
        def secret_key(self, v):
            raise RuntimeError("nope")

        # _sk assignment fails
        @property
        def _sk(self):
            return b"x"

        @_sk.setter
        def _sk(self, v):
            raise RuntimeError("nope")

        def sign(self, msg, priv=None):
            if priv is None:
                raise TypeError("need priv")
            return b"SIG2"

    class OQS:
        def Signature(self, alg, **kwargs):
            if kwargs:
                raise TypeError("ctor kwargs not supported")
            return _Ctx(Signer())

    sig = sign_ml_dsa(oqs=OQS(), msg=b"m", priv=b"p")
    assert sig == b"SIG2"


def test_ml_dsa_old_api_none_signature_is_fail_closed() -> None:
    # Hits pqc_ml_dsa line 63 (None) and outer cleanup path
    class Signer:
        def sign(self, msg, priv=None):
            return None

    class OQS:
        def Signature(self, alg, **kwargs):
            if kwargs:
                raise TypeError("ctor kwargs not supported")
            return _Ctx(Signer())

    with pytest.raises(RuntimeError):
        sign_ml_dsa(oqs=OQS(), msg=b"m", priv=b"p")


def test_ml_dsa_verify_exception_is_fail_closed() -> None:
    # Hits pqc_ml_dsa verify exception branch (84-85 + return False)
    class Verifier:
        def verify(self, msg, sig, pub):
            raise RuntimeError("boom")

    class OQS:
        def Signature(self, alg):
            return _Ctx(Verifier())

    assert verify_ml_dsa(oqs=OQS(), msg=b"m", sig=b"s", pub=b"p") is False


def test_falcon_ctor_kwargs_then_sign_typeerror_fallback() -> None:
    # Hits pqc_falcon 25-26 (sign(msg) TypeError -> sign(msg, priv))
    class Signer:
        def sign(self, msg, priv=None):
            if priv is None:
                raise TypeError("need priv")
            return b"FSIG"

    class OQS:
        def Signature(self, alg, **kwargs):
            return _Ctx(Signer())

    sig = sign_falcon(oqs=OQS(), msg=b"m", priv=b"p")
    assert sig == b"FSIG"


def test_falcon_ctor_kwargs_returns_none_is_fail_closed() -> None:
    # Hits pqc_falcon 28 (None) + exception cleanup (48-49) + RuntimeError
    class Signer:
        def sign(self, msg, priv=None):
            return None

    class OQS:
        def Signature(self, alg, **kwargs):
            return _Ctx(Signer())

    with pytest.raises(RuntimeError):
        sign_falcon(oqs=OQS(), msg=b"m", priv=b"p")


def test_falcon_old_api_none_signature_is_fail_closed() -> None:
    # Forces ctor kwargs to TypeError so code goes to older API branch, then None at line 42
    class Signer:
        def sign(self, msg, priv=None):
            return None

    class OQS:
        def Signature(self, alg, **kwargs):
            if kwargs:
                raise TypeError("ctor kwargs not supported")
            return _Ctx(Signer())

    with pytest.raises(RuntimeError):
        sign_falcon(oqs=OQS(), msg=b"m", priv=b"p")


def test_falcon_verify_exception_is_fail_closed() -> None:
    # Hits pqc_falcon verify exception branch (63-64 + return False)
    class Verifier:
        def verify(self, msg, sig, pub):
            raise RuntimeError("boom")

    class OQS:
        def Signature(self, alg):
            return _Ctx(Verifier())

    assert verify_falcon(oqs=OQS(), msg=b"m", sig=b"s", pub=b"p") is False
