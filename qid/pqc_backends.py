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

from qid.algorithms import FALCON_ALGO, HYBRID_ALGO, ML_DSA_ALGO


class PQCBackendError(RuntimeError):
    pass


class _OQSUnset:
    pass


_OQS_UNSET = _OQSUnset()

# Tests may monkeypatch this to:
# - None (meaning: explicitly unavailable)
# - a module-like object (meaning: "cached oqs module", avoid importing real optional dep)
oqs: Any = _OQS_UNSET


# Prefer modern NIST names, but support legacy Dilithium naming via fallback.
_OQS_ALG_BY_QID = {
    ML_DSA_ALGO: "ML-DSA-44",
    FALCON_ALGO: "Falcon-512",
}


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


def _oqs_alg_candidates_for(qid_alg: str) -> tuple[str, ...]:
    """
    Return candidate liboqs algorithm names for a given Q-ID alg.

    Must raise ValueError for unsupported algs (tests rely on this),
    and must list modern name first.
    """
    if qid_alg not in _OQS_ALG_BY_QID:
        raise ValueError(f"Unsupported algorithm for liboqs: {qid_alg!r}")

    primary = _OQS_ALG_BY_QID[qid_alg]

    if qid_alg == ML_DSA_ALGO:
        # Back-compat: older python-oqs/liboqs stacks used Dilithium2 naming.
        return (primary, "Dilithium2")

    return (primary,)


def _oqs_alg_for(qid_alg: str) -> str:
    """
    Back-compat shim for tests that expect _oqs_alg_for().

    Returns the *primary* liboqs algorithm name for a Q-ID alg.
    Raises ValueError for unsupported algs (as tests require).
    """
    return _oqs_alg_candidates_for(qid_alg)[0]


def _validate_oqs_module(mod: Any) -> None:
    sig = getattr(mod, "Signature", None)
    if sig is None or not callable(sig):
        raise PQCBackendError("Invalid oqs backend object: missing callable Signature")


def _import_oqs() -> Any:
    """
    Import (or return cached) oqs module.

    Critical test contracts:
    - If tests inject a cached module-like object into `qid.pqc_backends.oqs`
      AND backend is selected as liboqs, we must use that and NOT import.
    - If oqs is None, treat as unavailable and raise PQCBackendError.
    - If oqs is unset, attempt real import (may fail and raise PQCBackendError).
    """
    global oqs

    backend = selected_backend()

    if oqs is None:
        raise PQCBackendError("QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available.")

    if backend == "liboqs" and oqs is not _OQS_UNSET:
        _validate_oqs_module(oqs)
        return oqs

    if backend != "liboqs":
        raise PQCBackendError("No real PQC backend selected.")

    try:
        import oqs as real_oqs
    except Exception as e:
        raise PQCBackendError("QID_PQC_BACKEND=liboqs selected but 'oqs' module is not available.") from e

    _validate_oqs_module(real_oqs)
    oqs = real_oqs
    return real_oqs


def _build_sig_ctx(oqs_mod: Any, qid_alg: str, *, secret_key: bytes | None = None) -> Any:
    last_error: Exception | None = None

    for oqs_alg in _oqs_alg_candidates_for(qid_alg):
        try:
            if secret_key is None:
                return oqs_mod.Signature(oqs_alg)
            return oqs_mod.Signature(oqs_alg, secret_key)
        except Exception as e:
            last_error = e
            continue

    raise PQCBackendError(f"Unsupported liboqs signature algorithm for {qid_alg!r}") from last_error


def enforce_no_silent_fallback_for_alg(qid_alg: str) -> None:
    """
    Enforce that when a backend is explicitly selected, supported PQC algs
    are wired to that backend and must not silently downgrade.

    Contract:
    - For unsupported Q-ID algs, raise ValueError.
    - For DEV / stub mode, caller should not invoke this helper.
    - For HYBRID, require backend availability even though the actual signing/verifying
      happens as two concrete ops (ML-DSA + Falcon).
    """
    if qid_alg not in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
        raise ValueError(f"Unsupported Q-ID algorithm for real PQC backend: {qid_alg!r}")

    backend = selected_backend()
    if backend is None:
        raise PQCBackendError("No PQC backend selected.")
    if backend != "liboqs":
        raise PQCBackendError(f"Unsupported PQC backend: {backend!r}")

    _import_oqs()


def liboqs_sign(qid_alg: str, message: bytes, secret_key: bytes) -> bytes:
    """
    Sign using liboqs-selected backend.

    Raises:
    - ValueError for unsupported algs
    - PQCBackendError for backend wiring / availability problems
    """
    enforce_no_silent_fallback_for_alg(qid_alg)

    if qid_alg == HYBRID_ALGO:
        raise ValueError("HYBRID signing must be performed as two concrete liboqs_sign calls")

    oqs_mod = _import_oqs()
    try:
        sig_ctx = _build_sig_ctx(oqs_mod, qid_alg, secret_key=secret_key)
        return sig_ctx.sign(message)
    except PQCBackendError:
        raise
    except Exception as e:
        raise PQCBackendError(f"liboqs sign failed for algorithm {qid_alg!r}") from e


def liboqs_verify(qid_alg: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify using liboqs-selected backend.

    Returns False on signature mismatch / verification failure.
    Raises PQCBackendError only for backend wiring/availability problems.
    """
    enforce_no_silent_fallback_for_alg(qid_alg)

    if qid_alg == HYBRID_ALGO:
        raise ValueError("HYBRID verification must be performed as two concrete liboqs_verify calls")

    oqs_mod = _import_oqs()
    try:
        sig_ctx = _build_sig_ctx(oqs_mod, qid_alg)
        return bool(sig_ctx.verify(message, signature, public_key))
    except PQCBackendError:
        raise
    except Exception:
        return False
