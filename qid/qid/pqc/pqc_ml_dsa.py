"""
ML-DSA (Dilithium-family) wiring via liboqs.

Note:
liboqs (python-oqs) exposes Dilithium* algorithm names.
Q-ID uses the public label "pqc-ml-dsa" for the ML-DSA family.
"""

from __future__ import annotations

from typing import Any

OQS_ALG_ML_DSA_DEFAULT = "Dilithium2"


def sign_ml_dsa(*, oqs: Any, msg: bytes, priv: bytes, oqs_alg: str = OQS_ALG_ML_DSA_DEFAULT) -> bytes:
    with oqs.Signature(oqs_alg) as signer:
        return signer.sign(msg, priv)


def verify_ml_dsa(*, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str = OQS_ALG_ML_DSA_DEFAULT) -> bool:
    with oqs.Signature(oqs_alg) as verifier:
        return bool(verifier.verify(msg, sig, pub))
