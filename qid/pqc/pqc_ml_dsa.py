from __future__ import annotations

from typing import Any


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    alg = oqs_alg or "Dilithium2"
    signer = oqs.Signature(alg)

    # Newer python-oqs: import_secret_key + sign(msg)
    if hasattr(signer, "import_secret_key"):
        with signer as s:
            s.import_secret_key(priv)  # type: ignore[attr-defined]
            return s.sign(msg)

    # Older / dummy test double: sign(msg, priv)
    with signer as s:
        try:
            return s.sign(msg, priv)
        except TypeError:
            # Some variants are sign(msg) only (key provided elsewhere).
            return s.sign(msg)


def verify_ml_dsa(
    *,
    oqs: Any,
    msg: bytes,
    sig: bytes,
    pub: bytes,
    oqs_alg: str | None = None,
) -> bool:
    alg = oqs_alg or "Dilithium2"
    verifier = oqs.Signature(alg)

    if hasattr(verifier, "import_public_key"):
        with verifier as v:
            v.import_public_key(pub)  # type: ignore[attr-defined]
            return bool(v.verify(msg, sig))

    with verifier as v:
        try:
            return bool(v.verify(msg, sig, pub))
        except TypeError:
            return bool(v.verify(msg, sig))
