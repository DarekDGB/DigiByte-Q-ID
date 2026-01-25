"""
PQC backend selection + wiring for DigiByte Q-ID.

Design goals (contract + tests):
- CI-safe by default: no pqc deps required unless user explicitly selects a backend.
- No silent fallback: if a real backend is selected, PQC algs MUST NOT silently degrade.
- Deterministic behavior:
  - sign paths may raise PQCBackendError when backend selected but unavailable.
  - verify paths MUST fail-closed (return False) on internal errors.
"""

from __future__ import annotations

from typing import Any
import os


# These constants are also imported by tests.
ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "pqc-hybrid-ml-dsa-falcon"


class PQCBackendError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# liboqs import handling (deterministic + test-coverable)
# ---------------------------------------------------------------------------

_OQS_CACHE: Any | None = None


def _import_oqs() -> Any:
    """
    Import and cache python-oqs.

    Tests expect:
    - PQCBackendError when oqs cannot be imported
    - Deterministic behavior when import is monkeypatched
    """
    global _OQS_CACHE

    if _OQS_CACHE is not None:
        return _OQS_CACHE

    try:
        import oqs  # type: ignore
    except Exception as e:
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available. "
            'Install optional deps: pip install "git+https://github.com/open-quantum-safe/liboqs-python.git"'
        ) from e

    _validate_oqs_module(oqs)
    _OQS_CACHE = oqs
    return oqs


def _validate_oqs_module(mod: Any) -> None:
    """
    Validate that `mod` looks like python-oqs.

    Tests expect PQCBackendError when invalid.
    """
    sig = getattr(mod, "Signature", None)
    if sig is None or not callable(sig):
        raise PQCBackendError("Invalid oqs backend object: missing callable Signature")


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

def selected_backend() -> str | None:
    """
    Return normalized selected backend from env var QID_PQC_BACKEND.

    - None means "stub mode" (CI-safe).
    - "liboqs" means "real PQC backend expected".
    """
    raw = os.getenv("QID_PQC_BACKEND")
    if raw is None:
        return None
    s = raw.strip().lower()
    return s or None


def require_real_pqc() -> bool:
    """True when user explicitly selected a real PQC backend."""
    return selected_backend() is not None


# ---------------------------------------------------------------------------
# Algorithm mapping
# ---------------------------------------------------------------------------

_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "Dilithium2",
    FALCON_ALGO: "Falcon-512",
}


def _oqs_alg_for(qid_alg: str) -> str:
    """
    Convert Q-ID alg identifier to liboqs algorithm name.

    IMPORTANT:
    - For non-PQC algs, this MUST raise ValueError (not PQCBackendError).
    """
    if qid_alg not in _OQS_ALG_BY_QID:
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")
    return _OQS_ALG_BY_QID[qid_alg]


# ---------------------------------------------------------------------------
# Guardrail
# ---------------------------------------------------------------------------

def enforce_no_silent_fallback_for_alg(qid_alg: str) -> None:
    """
    Guardrail: if a real backend is selected, PQC algorithms must NOT silently fall back.

    Behavior:
    - unknown backend -> PQCBackendError
    - liboqs selected but oqs missing -> PQCBackendError for PQC algs
    - backend not selected -> no-op
    """
    backend = selected_backend()
    if backend is None:
        return

    if backend != "liboqs":
        raise PQCBackendError(f"Unknown QID_PQC_BACKEND: {backend!r}")

    if qid_alg not in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        return

    mod = _import_oqs()
    _validate_oqs_module(mod)


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------

def liboqs_sign(qid_alg: str, msg: bytes, priv: bytes) -> bytes:
    """
    Low-level sign using python-oqs.

    Contract:
    - Unsupported alg -> ValueError (before importing oqs)
    - Invalid oqs backend -> PQCBackendError
    - Signature ctor TypeError -> PQCBackendError
    """
    oqs_alg = _oqs_alg_for(qid_alg)
    mod = _import_oqs()
    _validate_oqs_module(mod)

    try:
        if qid_alg == ML_DSA_ALGO:
            from qid.pqc.pqc_ml_dsa import sign_ml_dsa

            return sign_ml_dsa(
                oqs=mod,
                msg=msg,
                priv=priv,
                oqs_alg=oqs_alg,
            )

        if qid_alg == FALCON_ALGO:
            from qid.pqc.pqc_falcon import sign_falcon

            return sign_falcon(
                oqs=mod,
                msg=msg,
                priv=priv,
                oqs_alg=oqs_alg,
            )

        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    except TypeError as e:
        raise PQCBackendError(
            "liboqs signing failed (Signature ctor rejected inputs)"
        ) from e
    except PQCBackendError:
        raise
    except Exception as e:  # pragma: no cover
        raise PQCBackendError("liboqs signing failed") from e


def liboqs_verify(qid_alg: str, msg: bytes, sig: bytes, pub: bytes) -> bool:
    """
    Low-level verify using python-oqs.

    Contract:
    - Invalid backend object -> PQCBackendError (not swallowed)
    - Unsupported alg -> ValueError
    - Internal verifier error -> False (fail-closed)
    """
    oqs_alg = _oqs_alg_for(qid_alg)
    mod = _import_oqs()
    _validate_oqs_module(mod)

    try:
        if qid_alg == ML_DSA_ALGO:
            from qid.pqc.pqc_ml_dsa import verify_ml_dsa

            return bool(
                verify_ml_dsa(
                    oqs=mod,
                    msg=msg,
                    sig=sig,
                    pub=pub,
                    oqs_alg=oqs_alg,
                )
            )

        if qid_alg == FALCON_ALGO:
            from qid.pqc.pqc_falcon import verify_falcon

            return bool(
                verify_falcon(
                    oqs=mod,
                    msg=msg,
                    sig=sig,
                    pub=pub,
                    oqs_alg=oqs_alg,
                )
            )

        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    except (ValueError, PQCBackendError):
        raise
    except Exception:
        return False
