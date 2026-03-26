"""
PQC backend selection + wiring for DigiByte Q-ID.

Design goals (contract + tests):
- CI-safe by default: no pqc deps required unless user explicitly selects a backend.
- No silent fallback: if a real backend is selected, PQC algs MUST NOT silently degrade.
- Deterministic behavior:
  - sign paths may raise PQCBackendError when backend selected but unavailable.
  - verify paths MUST fail-closed (return False) on signature/verification errors,
    but MUST raise PQCBackendError on backend wiring/validation problems (tests rely on this).
"""

from __future__ import annotations

import os
from typing import Any

from qid.algorithms import DEV_ALGO, FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO


class PQCBackendError(RuntimeError):
    pass


class _OQSUnset:
    pass


_OQS_UNSET = _OQSUnset()

# Tests may monkeypatch this
oqs: Any = _OQS_UNSET


_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "ML-DSA-44",
    FALCON_ALGO: "Falcon-512",
}


def selected_backend() -> str | None:
    raw = os.getenv("QID_PQC_BACKEND")
    if raw is None:
        return None
    s = raw.strip().lower()
    return s or None


def require_real_pqc() -> bool:
    return selected_backend() is not None


def _oqs_alg_candidates_for(qid_alg: str) -> tuple[str, ...]:
    if qid_alg not in _OQS_ALG_BY_QID:
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    primary = _OQS_ALG_BY_QID[qid_alg]
    if qid_alg == ML_DSA_ALGO:
        return (primary, "Dilithium2")
    return (primary,)


def _oqs_alg_for(qid_alg: str) -> str:
    return _oqs_alg_candidates_for(qid_alg)[0]


def _validate_oqs_module(mod: Any) -> None:
    sig = getattr(mod, "Signature", None)
    if sig is None or not callable(sig):
        raise PQCBackendError("Invalid oqs backend object: missing callable Signature")


def _import_oqs() -> Any:
    global oqs

    backend = selected_backend()

    if oqs is None:
        raise PQCBackendError("QID_PQC_BACKEND=liboqs selected but oqs not available")

    if backend == "liboqs" and oqs is not _OQS_UNSET:
        _validate_oqs_module(oqs)
        return oqs

    if backend != "liboqs":
        raise PQCBackendError("No real PQC backend selected")

    try:
        import oqs as real_oqs
    except Exception as e:
        raise PQCBackendError("oqs import failed") from e

    _validate_oqs_module(real_oqs)
    oqs = real_oqs
    return real_oqs


def enforce_no_silent_fallback_for_alg(qid_alg: str) -> None:
    if qid_alg == DEV_ALGO:
        return

    if qid_alg not in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    backend = selected_backend()
    if backend is None:
        return

    if backend != "liboqs":
        raise PQCBackendError(f"Unsupported PQC backend: {backend!r}")

    mod = _import_oqs()
    _validate_oqs_module(mod)


# ---------------- SIGN ----------------


def liboqs_sign(qid_alg: str, message: bytes, secret_key: bytes) -> bytes:
    # use resolver (tests may patch it)
    try:
        _oqs_alg_candidates_for(qid_alg)
    except ValueError:
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    try:
        enforce_no_silent_fallback_for_alg(qid_alg)

        mod = _import_oqs()
        _validate_oqs_module(mod)

        if qid_alg == ML_DSA_ALGO:
            from qid.pqc.pqc_ml_dsa import sign_ml_dsa
            return sign_ml_dsa(message, secret_key)

        if qid_alg == FALCON_ALGO:
            from qid.pqc.pqc_falcon import sign_falcon
            return sign_falcon(message, secret_key)

        raise PQCBackendError("liboqs signing failed")

    except PQCBackendError:
        raise
    except Exception as e:
        raise PQCBackendError("liboqs signing failed") from e


# ---------------- VERIFY ----------------


def liboqs_verify(qid_alg: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        _oqs_alg_candidates_for(qid_alg)
    except ValueError:
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    try:
        enforce_no_silent_fallback_for_alg(qid_alg)

        mod = _import_oqs()
        _validate_oqs_module(mod)

        if qid_alg == ML_DSA_ALGO:
            from qid.pqc.pqc_ml_dsa import verify_ml_dsa
            return bool(verify_ml_dsa(message, signature, public_key))

        if qid_alg == FALCON_ALGO:
            from qid.pqc.pqc_falcon import verify_falcon
            return bool(verify_falcon(message, signature, public_key))

        return False

    except PQCBackendError:
        raise
    except Exception:
        return False
