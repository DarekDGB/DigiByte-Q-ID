from __future__ import annotations

from typing import Any


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    """
    ML-DSA signing via python-oqs.

    CRITICAL SAFETY RULE:
    - Never allow oqs.Signature objects to leak into exception context
      (pytest repr can segfault).
    """
    alg = oqs_alg or "Dilithium2"
    signer = None

    try:
        with oqs.Signature(alg) as signer:
            if hasattr(signer, "import_secret_key"):
                signer.import_secret_key(priv)  # type: ignore[attr-defined]
                return signer.sign(msg)

            # Older API variants
            try:
                return signer.sign(msg, priv)
            except TypeError:
                return signer.sign(msg)

    except Exception:
        # MUST delete signer to prevent pytest repr segfault
        try:
            del signer
        except Exception:
            pass

        # Clean failure, no chained exception
        raise RuntimeError("pqc_ml_dsa signing failed") from None


def verify_ml_dsa(
    *,
    oqs: Any,
    msg: bytes,
    sig: bytes,
    pub: bytes,
    oqs_alg: str | None = None,
) -> bool:
    """
    ML-DSA verify — fail closed.
    """
    alg = oqs_alg or "Dilithium2"
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
