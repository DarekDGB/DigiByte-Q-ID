from __future__ import annotations

from typing import Any

from qid.pqc.pqc_ml_dsa import _set_secret_key


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """
    Falcon signing via python-oqs.

    Compatibility rule (deterministic, fail-closed):
    - Prefer APIs that accept `sign(msg, priv)` (used by DummyOQS tests).
    - Otherwise fall back to secret-key import + `sign(msg)`.
    """
    alg = oqs_alg or "Falcon-512"
    signer = None
    try:
        with oqs.Signature(alg) as signer:
            # First try the API that accepts priv directly (DummyOQS style).
            try:
                sig = signer.sign(msg, priv)
                if sig is None:
                    raise RuntimeError("signer.sign() returned None")
                return sig
            except TypeError:
                pass

            # If that fails, try importing secret key then sign(msg).
            _set_secret_key(signer, priv)

            try:
                sig = signer.sign(msg)
            except TypeError:
                sig = signer.sign(msg, priv)

            if sig is None:
                raise RuntimeError("signer.sign() returned None")
            return sig

    except Exception:
        try:
            del signer
        except Exception:  # pragma: no cover
            pass
        raise RuntimeError("pqc_falcon signing failed") from None


def verify_falcon(*, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str | None = None) -> bool:
    """
    Falcon verify via python-oqs.

    Fail-closed: any exception => False.
    """
    alg = oqs_alg or "Falcon-512"
    verifier = None
    try:
        with oqs.Signature(alg) as verifier:
            return bool(verifier.verify(msg, sig, pub))
    except Exception:
        try:
            del verifier
        except Exception:  # pragma: no cover
            pass
        return False
