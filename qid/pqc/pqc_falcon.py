from __future__ import annotations

from typing import Any


def sign_falcon(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """
    Falcon signing via python-oqs.

    Same safety rules as ML-DSA.
    """
    alg = oqs_alg or "Falcon-512"
    signer = None

    try:
        with oqs.Signature(alg) as signer:
            if hasattr(signer, "import_secret_key"):
                signer.import_secret_key(priv)  # type: ignore[attr-defined]
                return signer.sign(msg)

            try:
                return signer.sign(msg, priv)
            except TypeError:
                return signer.sign(msg)

    except Exception:
        try:
            del signer
        except Exception:
            pass
        raise RuntimeError("pqc_falcon signing failed") from None


def verify_falcon(
    *,
    oqs: Any,
    msg: bytes,
    sig: bytes,
    pub: bytes,
    oqs_alg: str | None = None,
) -> bool:
    """
    Falcon verify — fail closed.
    """
    alg = oqs_alg or "Falcon-512"
    verifier = None

    try:
        with oqs.Signature(alg) as verifier:
            return bool(verifier.verify(msg, sig, pub))

    except Exception:
        try:
            del verifier
        except Exception:
            pass
        return False
