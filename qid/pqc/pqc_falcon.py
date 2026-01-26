from __future__ import annotations

from typing import Any


def _sign_with_signature(sig_obj: Any, msg: bytes, priv: bytes) -> bytes:
    """
    Sign message using a Signature instance, predicted python-oqs variants:
    - import_secret_key(priv) + sign(msg)
    - sign(msg, priv)
    - sign(msg) after construction with secret_key=priv
    """
    if hasattr(sig_obj, "import_secret_key") and callable(getattr(sig_obj, "import_secret_key")):
        sig_obj.import_secret_key(priv)
        return bytes(sig_obj.sign(msg))

    try:
        return bytes(sig_obj.sign(msg, priv))
    except TypeError:
        return bytes(sig_obj.sign(msg))


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """Falcon signing via oqs.Signature — may raise on backend errors."""
    alg = oqs_alg or "Falcon-512"

    # Try modern python-oqs style: Signature(alg, secret_key=priv)
    try:
        signer = oqs.Signature(alg, secret_key=priv)
        if hasattr(signer, "__enter__") and hasattr(signer, "__exit__"):
            with signer as s:
                return bytes(s.sign(msg))
        return bytes(signer.sign(msg))
    except TypeError:
        pass

    # Fallback style
    signer = oqs.Signature(alg)
    if hasattr(signer, "__enter__") and hasattr(signer, "__exit__"):
        with signer as s:
            return _sign_with_signature(s, msg, priv)

    return _sign_with_signature(signer, msg, priv)


def verify_falcon(
    *, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str | None = None
) -> bool:
    """Falcon verify — must fail-closed (return False) on internal errors."""
    alg = oqs_alg or "Falcon-512"

    verifier = None
    try:
        verifier = oqs.Signature(alg)

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
