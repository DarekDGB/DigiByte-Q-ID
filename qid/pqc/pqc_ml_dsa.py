from __future__ import annotations
from typing import Any


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str | None = None) -> bytes:
    alg = oqs_alg or "Dilithium2"

    with oqs.Signature(alg, secret_key=priv) as signer:
        return signer.sign(msg)


def verify_ml_dsa(
    *,
    oqs: Any,
    msg: bytes,
    sig: bytes,
    pub: bytes,
    oqs_alg: str | None = None,
) -> bool:
    alg = oqs_alg or "Dilithium2"

    with oqs.Signature(alg) as verifier:
        return bool(verifier.verify(msg, sig, pub))
