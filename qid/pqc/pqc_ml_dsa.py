from __future__ import annotations

from typing import Any


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    alg = oqs_alg or "Dilithium2"

    signer = None  # IMPORTANT: we will del this on error to avoid pytest repr segfaults
    try:
        with oqs.Signature(alg) as signer:
            # Newer python-oqs API: import_secret_key + sign(msg)
            if hasattr(signer, "import_secret_key"):
                signer.import_secret_key(priv)  # type: ignore[attr-defined]
                return signer.sign(msg)

            # Dummy / older API variants:
            try:
                return signer.sign(msg, priv)
            except TypeError:
                return signer.sign(msg)

    except Exception:
        # Critical: remove the Signature instance from locals BEFORE bubbling up.
        try:
            del signer
        except Exception:
            pass
        # Re-raise a clean error WITHOUT attaching the original exception context.
        raise RuntimeError("pqc_ml_dsa signing failed") from None


def verify_ml_dsa(
    *,
    oqs: Any,
    msg: bytes,
    sig: bytes,
    pub: bytes,
    oqs_alg: str | None = None,
) -> bool:
    alg = oqs_alg or "Dilithium2"

    verifier = None  # IMPORTANT: del on error to avoid pytest repr segfaults
    try:
        with oqs.Signature(alg) as verifier:
            if hasattr(verifier, "import_public_key"):
                verifier.import_public_key(pub)  # type: ignore[attr-defined]
                return bool(verifier.verify(msg, sig))

            try:
                return bool(verifier.verify(msg, sig, pub))
            except TypeError:
                return bool(verifier.verify(msg, sig))

    except Exception:
        try:
            del verifier
        except Exception:
            pass
        # Fail-closed
        return False
