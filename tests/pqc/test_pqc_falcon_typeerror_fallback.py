from qid.pqc.pqc_falcon import sign_falcon


class _Ctx:
    def __init__(self, obj):
        self._obj = obj

    def __enter__(self):
        return self._obj

    def __exit__(self, exc_type, exc, tb):
        return False


def test_falcon_sign_typeerror_then_sign_with_priv_path() -> None:
    class Signer:
        def sign(self, msg, priv=None):
            if priv is None:
                raise TypeError("need priv")
            return b"FSIG"

    class OQS:
        def Signature(self, alg, **kwargs):
            return _Ctx(Signer())

    sig = sign_falcon(oqs=OQS(), msg=b"m", priv=b"p", oqs_alg="Falcon-512")
    assert sig == b"FSIG"
