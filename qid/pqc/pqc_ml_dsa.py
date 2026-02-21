from __future__ import annotations

from typing import Any


def _set_secret_key(signer: Any, priv: bytes) -> None:
    """Best-effort secret key import across python-oqs API variants."""
    if hasattr(signer, "import_secret_key"):
        signer.import_secret_key(priv)  # type: ignore[attr-defined]
        return

    # Some variants expose a writable attribute.
    if hasattr(signer, "secret_key"):
        try:
            signer.secret_key = priv  # type: ignore[attr-defined]
            return
        except Exception:
            pass

    # Some variants use a private attr.
    if hasattr(signer, "_sk"):
        try:
            signer._sk = priv  # type: ignore[attr-defined]
            return
        except Exception:
            pass

    raise RuntimeError("Unable to import secret key into oqs.Signature object")


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """
    ML-DSA signing via python-oqs.

    Compatibility rule (deterministic, fail-closed):
    - Prefer APIs that accept `sign(msg, priv)` (used by DummyOQS tests).
    - Otherwise fall back to secret-key import + `sign(msg)`.
    """
    alg = oqs_alg or "ML-DSA-44"
    signer = None
    try:
        # Newer API: allow secret_key kwarg at ctor (if supported).
        try:
            with oqs.Signature(alg, secret_key=priv) as signer:
                try:
                    sig = signer.sign(msg)
                except TypeError:
                    sig = signer.sign(msg, priv)

                if sig is None:
                    raise RuntimeError("signer.sign() returned None")
                return sig
        except TypeError:
            # Older API: ctor kwargs not supported.
            with oqs.Signature(alg) as signer:
                # First try the API that accepts priv directly (DummyOQS style).
                try:
                    sig = signer.sign(msg, priv)
                    if sig is None:
                        raise RuntimeError("signer.sign() returned None")
                    return sig
                except TypeError:
                    pass

                # If that fails, try importing the secret key then sign(msg).
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
        raise RuntimeError("pqc_ml_dsa signing failed") from None


def verify_ml_dsa(*, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str | None = None) -> bool:
    """
    ML-DSA verify via python-oqs.

    Fail-closed: any exception => False.
    """
    alg = oqs_alg or "ML-DSA-44"
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
