from __future__ import annotations

import os
from typing import Tuple, Any


class PQCBackendError(RuntimeError):
    """Raised when a real PQC backend is required but unavailable."""


class PQCAlgorithmError(ValueError):
    """Raised when an unsupported PQC algorithm is requested."""


# Explicit allowlist — single source of truth
ALLOWED_ML_DSA_ALGS = {
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
}

ALLOWED_FALCON_ALGS = {
    "Falcon-512",
    "Falcon-1024",
}

# Alias map for environments where python-oqs/liboqs exposes Dilithium*
# rather than ML-DSA-* names (or vice versa).
_ML_DSA_TO_OQS_FALLBACK = {
    "ML-DSA-44": "Dilithium2",
    "ML-DSA-65": "Dilithium3",
    "ML-DSA-87": "Dilithium5",
}


def _require_liboqs_backend_selected() -> None:
    if os.environ.get("QID_PQC_BACKEND") != "liboqs":
        raise PQCBackendError("liboqs backend not enabled (QID_PQC_BACKEND!=liboqs)")


def _import_oqs() -> Any:
    """
    Reuse the same deterministic import/cache behavior as qid.pqc_backends.

    This prevents flaky CI behavior and ensures monkeypatched import paths
    behave as tests expect.
    """
    _require_liboqs_backend_selected()
    try:
        from qid import pqc_backends as pb
    except Exception:
        raise PQCBackendError("Internal error: cannot import qid.pqc_backends") from None

    # pb._import_oqs already implements the "oqs=None / unset / cached" behavior.
    try:
        return pb._import_oqs()  # type: ignore[attr-defined]
    except Exception:
        raise PQCBackendError("liboqs-python not installed or failed to import") from None


def _enabled_sig_algs(oqs_mod: Any) -> set[str]:
    sig_cls = getattr(oqs_mod, "Signature", None)
    if sig_cls is None:
        return set()
    fn = getattr(sig_cls, "get_enabled_sig_algs", None)
    if callable(fn):
        try:
            return set(fn())
        except Exception:
            return set()
    return set()


def _resolve_ml_dsa_alg(oqs_mod: Any, requested: str) -> str:
    """
    Prefer ML-DSA-* names if available; otherwise fall back to Dilithium*.
    """
    enabled = _enabled_sig_algs(oqs_mod)
    if requested in enabled:
        return requested

    fallback = _ML_DSA_TO_OQS_FALLBACK.get(requested)
    if fallback and fallback in enabled:
        return fallback

    # If enabled list isn't available, still try the requested name first,
    # then the fallback — but raise cleanly if both fail.
    return requested if fallback is None else requested  # try requested first in caller


def _resolve_falcon_alg(oqs_mod: Any, requested: str) -> str:
    enabled = _enabled_sig_algs(oqs_mod)
    if not enabled:
        return requested
    if requested in enabled:
        return requested
    raise PQCAlgorithmError(f"Falcon algorithm not available in liboqs: {requested}")


def generate_ml_dsa_keypair(alg: str) -> Tuple[bytes, bytes]:
    # Fail-closed early on invalid algorithm (does not depend on backend availability)
    if alg not in ALLOWED_ML_DSA_ALGS:
        raise PQCAlgorithmError(f"ML-DSA algorithm not allowed: {alg}")

    oqs_mod = _import_oqs()

    signer = None
    # Prefer ML-DSA-* if supported, otherwise try Dilithium fallback.
    primary = _resolve_ml_dsa_alg(oqs_mod, alg)
    fallback = _ML_DSA_TO_OQS_FALLBACK.get(alg)

    for candidate in [primary, fallback]:
        if not candidate:
            continue
        try:
            with oqs_mod.Signature(candidate) as signer:
                public_key = signer.generate_keypair()
                secret_key = signer.export_secret_key()
            return public_key, secret_key
        except Exception:
            try:
                del signer
            except Exception:
                pass
            continue

    raise PQCBackendError(f"liboqs could not create ML-DSA signer for {alg}") from None


def generate_falcon_keypair(alg: str) -> Tuple[bytes, bytes]:
    # Fail-closed early on invalid algorithm (does not depend on backend availability)
    if alg not in ALLOWED_FALCON_ALGS:
        raise PQCAlgorithmError(f"Falcon algorithm not allowed: {alg}")

    oqs_mod = _import_oqs()
    resolved = _resolve_falcon_alg(oqs_mod, alg)

    signer = None
    try:
        with oqs_mod.Signature(resolved) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
        return public_key, secret_key
    except Exception:
        try:
            del signer
        except Exception:
            pass
        raise PQCBackendError(f"liboqs could not create Falcon signer for {alg}") from None
