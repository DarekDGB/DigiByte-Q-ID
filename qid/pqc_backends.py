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


# Map Q-ID alg identifiers to liboqs algorithm names.
# (Exact mapping can be adjusted later, but tests only require support gating.)
_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "Dilithium2",  # ML-DSA family mapping (via liboqs Dilithium*)
    FALCON_ALGO: "Falcon-512",
}


def selected_backend() -> str | None:
    """
    Return normalized selected backend from env var QID_PQC_BACKEND.

    - None means "stub mode" (CI-safe, uses local deterministic stubs).
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


def _oqs_alg_for(qid_alg: str) -> str:
    """
    Convert Q-ID alg identifier to liboqs algorithm name.

    IMPORTANT for tests:
    - For non-PQC algs, this must raise ValueError (not PQCBackendError).
    """
    if qid_alg not in _OQS_ALG_BY_QID:
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")
    return _OQS_ALG_BY_QID[qid_alg]


def _validate_oqs_module(oqs: Any) -> None:
    """
    Validate that `oqs` looks like python-oqs.

    Tests expect PQCBackendError when invalid.
    """
    sig = getattr(oqs, "Signature", None)
    if sig is None or not callable(sig):
        raise PQCBackendError("Invalid oqs backend object: missing callable Signature")


def _import_oqs() -> Any:
    """
    Import python-oqs when backend selected.
    In CI it is usually missing.

    Tests expect:
    - PQCBackendError when oqs is missing.
    """
    try:
        import oqs  # type: ignore
    except Exception as e:  # pragma: no cover
        raise PQCBackendError(
            "QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available. "
            'Install optional deps: pip install -e ".[dev,pqc]"'
        ) from e
    return oqs


def enforce_no_silent_fallback_for_alg(qid_alg: str) -> None:
    """
    Guardrail: if a real backend is selected, PQC algorithms must NOT silently fall back.

    Tests expect:
    - unknown backend -> PQCBackendError
    - liboqs selected but oqs missing -> PQCBackendError for PQC algs
    - when backend not selected -> do nothing
    """
    backend = selected_backend()
    if backend is None:
        return

    if backend != "liboqs":
        raise PQCBackendError(f"Unknown QID_PQC_BACKEND: {backend!r}")

    # Only enforce for PQC algorithms.
    if qid_alg not in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        return

    # If oqs isn't available, raise (CI expected behavior).
    oqs = _import_oqs()
    _validate_oqs_module(oqs)


def liboqs_sign(qid_alg: str, msg: bytes, priv: bytes) -> bytes:
    """
    Low-level sign using python-oqs.

    Tests require:
    - Unsupported alg -> ValueError (and MUST happen before import oqs).
    - Invalid oqs backend object -> PQCBackendError.
    - If Signature ctor raises TypeError -> PQCBackendError.
    """
    oqs_alg = _oqs_alg_for(qid_alg)  # ValueError for non-PQC algs (no oqs import)
    oqs = _import_oqs()
    _validate_oqs_module(oqs)

    try:
        if qid_alg == ML_DSA_ALGO:
            from qid.pqc.pqc_ml_dsa import sign_ml_dsa

            return sign_ml_dsa(oqs=oqs, msg=msg, priv=priv, oqs_alg=oqs_alg)

        if qid_alg == FALCON_ALGO:
            from qid.pqc.pqc_falcon import sign_falcon

            return sign_falcon(oqs=oqs, msg=msg, priv=priv, oqs_alg=oqs_alg)

        # HYBRID is signed in qid.crypto by calling liboqs_sign twice (strict AND envelope).
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    except TypeError as e:
        # Tests explicitly hit this branch.
        raise PQCBackendError("liboqs signing failed (Signature ctor rejected inputs)") from e
    except PQCBackendError:
        raise
    except Exception as e:  # pragma: no cover
        raise PQCBackendError("liboqs signing failed") from e


def liboqs_verify(qid_alg: str, msg: bytes, sig: bytes, pub: bytes) -> bool:
    """
    Low-level verify using python-oqs.

    Tests require:
    - Invalid backend object -> PQCBackendError (do NOT swallow).
    - Unsupported alg -> ValueError.
    - Internal verifier exception -> return False (fail-closed).
    """
    oqs_alg = _oqs_alg_for(qid_alg)  # ValueError for non-PQC algs
    oqs = _import_oqs()
    _validate_oqs_module(oqs)

    try:
        if qid_alg == ML_DSA_ALGO:
            from qid.pqc.pqc_ml_dsa import verify_ml_dsa

            return bool(verify_ml_dsa(oqs=oqs, msg=msg, sig=sig, pub=pub, oqs_alg=oqs_alg))

        if qid_alg == FALCON_ALGO:
            from qid.pqc.pqc_falcon import verify_falcon

            return bool(verify_falcon(oqs=oqs, msg=msg, sig=sig, pub=pub, oqs_alg=oqs_alg))

        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    except (ValueError, PQCBackendError):
        # Preserve strict errors for tests / callers.
        raise
    except Exception:
        # Fail-closed: verify never crashes callers.
        return False
