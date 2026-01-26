from __future__ import annotations

from typing import Any


def _sign_with_signature(sig_obj: Any, msg: bytes, priv: bytes) -> bytes:
    """
    Sign message using a Signature instance, supporting multiple APIs:
    - import_secret_key(priv) + sign(msg)
    - sign(msg, priv)
    - sign(msg) after construction with secret_key=priv
    """
    # Preferred: import_secret_key + sign(msg)
    if hasattr(sig_obj, "import_secret_key") and callable(getattr(sig_obj, "import_secret_key")):
        sig_obj.import_secret_key(priv)
        return bytes(sig_obj.sign(msg))

    # Fallback: sign(msg, priv)
    try:
        return bytes(sig_obj.sign(msg, priv))
    except TypeError:
        # Final fallback: sign(msg) only
        return bytes(sig_obj.sign(msg))


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """ML-DSA signing via oqs.Signature — may raise on backend errors."""
    alg = oqs_alg or "ML-DSA-44"

    # Try modern python-oqs style: Signature(alg, secret_key=priv)
    try:
        signer = oqs.Signature(alg, secret_key=priv)
        if hasattr(signer, "__enter__") and hasattr(signer, "__exit__"):
            with signer as s:
                return bytes(s.sign(msg))
        return bytes(signer.sign(msg))
    except TypeError:
        # Signature() doesn't accept secret_key kw → use fallback flow below
        pass

    # Fallback style: Signature(alg) then import_secret_key(priv) then sign(msg)
    signer = oqs.Signature(alg)
    if hasattr(signer, "__enter__") and hasattr(signer, "__exit__"):
        with signer as s:
            return _sign_with_signature(s, msg, priv)

    return _sign_with_signature(signer, msg, priv)


def verify_ml_dsa(
    *, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str | None = None
) -> bool:
    """ML-DSA verify — must fail-closed (return False) on internal errors."""
    alg = oqs_alg or "ML-DSA-44"

    verifier = None
    try:
        verifier = oqs.Signature(alg)

        # Support both newer python-oqs (context manager) and simple stubs used in tests.
        if hasattr(verifier, "__enter__") and hasattr(verifier, "__exit__"):
            with verifier as v:
                return bool(v.verify(msg, sig, pub))

        return bool(verifier.verify(msg, sig, pub))
    except Exception:
        return False
    finally:
        try:
            del verifier
        except Exception:
            pass
