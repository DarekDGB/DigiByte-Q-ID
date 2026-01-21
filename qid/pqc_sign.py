from __future__ import annotations

"""
Client-side PQC signing helpers for dual-proof Q-ID logins.

Contract:
- Produces fields on the login response payload:
  - pqc_alg
  - pqc_sig (single) OR pqc_sig_ml_dsa + pqc_sig_falcon (hybrid)
- Sign/verify input is the login payload with PQC signature fields removed (non-circular).
- No silent fallback:
  - If QID_PQC_BACKEND is set, the backend MUST exist and be used.
- This module is intentionally strict:
  - If no backend selected, it raises PQCBackendError (caller decides policy).
"""

import base64
import json
from typing import Any, Mapping, MutableMapping

from .pqc_backends import (
    ML_DSA_ALGO,
    FALCON_ALGO,
    HYBRID_ALGO,
    PQCBackendError,
    enforce_no_silent_fallback_for_alg,
    liboqs_sign,
    selected_backend,
)
from .crypto import QIDKeyPair

_SIG_FIELDS = {"pqc_sig", "pqc_sig_ml_dsa", "pqc_sig_falcon"}


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _payload_for_pqc(login_payload: Mapping[str, Any]) -> dict[str, Any]:
    d = dict(login_payload)
    for k in _SIG_FIELDS:
        d.pop(k, None)
    return d


def _decode_secret_key(kp: QIDKeyPair) -> bytes:
    if not isinstance(kp.secret_key, str) or not kp.secret_key:
        raise ValueError("missing secret_key")
    # keypairs in this repo use base64 standard w/ padding; urlsafe decode accepts it too.
    return _b64url_decode(kp.secret_key)


def sign_pqc_login_fields(
    payload: MutableMapping[str, Any],
    *,
    pqc_alg: str,
    ml_dsa_keypair: QIDKeyPair | None = None,
    falcon_keypair: QIDKeyPair | None = None,
) -> None:
    """
    Mutates payload in-place by adding PQC fields.

    Requirements:
    - QID_PQC_BACKEND must be selected (e.g. "liboqs"), otherwise raises PQCBackendError.
    - pqc_alg must be one of ML_DSA_ALGO / FALCON_ALGO / HYBRID_ALGO.
    - For HYBRID, both keypairs must be provided.
    """
    backend = selected_backend()
    if backend is None:
        raise PQCBackendError("No PQC backend selected (set QID_PQC_BACKEND=liboqs)")

    if pqc_alg not in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        raise ValueError(f"Unknown PQC algorithm: {pqc_alg!r}")

    # Enforce no silent fallback (also validates backend availability)
    enforce_no_silent_fallback_for_alg(pqc_alg)

    # Ensure payload has pqc_alg (covered by signature)
    payload["pqc_alg"] = pqc_alg

    msg = canonical_payload_bytes(_payload_for_pqc(payload))

    # Clear existing signatures before writing new ones
    for k in _SIG_FIELDS:
        payload.pop(k, None)

    if pqc_alg == ML_DSA_ALGO:
        if ml_dsa_keypair is None:
            raise ValueError("ml_dsa_keypair is required for ML-DSA signing")
        sec = _decode_secret_key(ml_dsa_keypair)
        sig = liboqs_sign(ML_DSA_ALGO, msg, sec)
        payload["pqc_sig"] = _b64url_encode(sig)
        return

    if pqc_alg == FALCON_ALGO:
        if falcon_keypair is None:
            raise ValueError("falcon_keypair is required for Falcon signing")
        sec = _decode_secret_key(falcon_keypair)
        sig = liboqs_sign(FALCON_ALGO, msg, sec)
        payload["pqc_sig"] = _b64url_encode(sig)
        return

    # HYBRID strict AND
    if ml_dsa_keypair is None or falcon_keypair is None:
        raise ValueError("Both ml_dsa_keypair and falcon_keypair are required for HYBRID signing")

    sec_ml = _decode_secret_key(ml_dsa_keypair)
    sec_fa = _decode_secret_key(falcon_keypair)
    sig_ml = liboqs_sign(ML_DSA_ALGO, msg, sec_ml)
    sig_fa = liboqs_sign(FALCON_ALGO, msg, sec_fa)
    payload["pqc_sig_ml_dsa"] = _b64url_encode(sig_ml)
    payload["pqc_sig_falcon"] = _b64url_encode(sig_fa)
