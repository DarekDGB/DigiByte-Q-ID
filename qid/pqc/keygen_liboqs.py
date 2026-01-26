from __future__ import annotations

import os
from typing import Any, Tuple

# NOTE:
# Tests monkeypatch `oqs` directly, so we keep a module-level `oqs` symbol.

try:  # pragma: no cover (covered in optional real-backend workflow)
    import oqs as oqs  # type: ignore
except Exception:  # pragma: no cover
    oqs = None  # type: ignore


class PQCBackendError(RuntimeError):
    """Raised when a real PQC backend is required but unavailable."""


class PQCAlgorithmError(ValueError):
    """Raised when an unsupported PQC algorithm is requested."""


# Explicit allowlists — single source of truth
ALLOWED_ML_DSA_ALGS = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}
ALLOWED_FALCON_ALGS = {"Falcon-512", "Falcon-1024"}

# liboqs/python-oqs historically exposes Dilithium* names for ML-DSA.
_ML_DSA_FALLBACK = {
    "ML-DSA-44": "Dilithium2",
    "ML-DSA-65": "Dilithium3",
    "ML-DSA-87": "Dilithium5",
}


def _require_liboqs() -> Any:
    """
    Guardrail for tests + callers:

    - If QID_PQC_BACKEND != 'liboqs' -> PQCBackendError
    - If oqs is unavailable (or tests force oqs=None) -> PQCBackendError
    - Otherwise return the oqs module-like object.
    """
    backend = os.environ.get("QID_PQC_BACKEND", "").strip().lower()
    if backend != "liboqs":
        raise PQCBackendError("liboqs backend not enabled (QID_PQC_BACKEND!=liboqs)")
    if oqs is None:
        raise PQCBackendError("liboqs backend selected but 'oqs' module is not available")
    return oqs


def _export_secret_key(signer: Any) -> bytes:
    """
    Export secret key across python-oqs API variants.

    We prefer explicit export methods, but support older/alternate attribute patterns.
    """
    if hasattr(signer, "export_secret_key"):
        sk = signer.export_secret_key()  # type: ignore[attr-defined]
        if isinstance(sk, (bytes, bytearray)):
            return bytes(sk)

    if hasattr(signer, "secret_key"):
        sk = signer.secret_key  # type: ignore[attr-defined]
        if isinstance(sk, (bytes, bytearray)):
            return bytes(sk)

    if hasattr(signer, "_sk"):
        sk = signer._sk  # type: ignore[attr-defined]
        if isinstance(sk, (bytes, bytearray)):
            return bytes(sk)

    raise PQCBackendError("liboqs signer did not expose a usable secret key export API")


def generate_ml_dsa_keypair(alg: str) -> Tuple[bytes, bytes]:
    # Fail-closed early on invalid algorithm (does not depend on backend availability)
    if alg not in ALLOWED_ML_DSA_ALGS:
        raise PQCAlgorithmError(f"ML-DSA algorithm not allowed: {alg}")

    mod = _require_liboqs()

    # Prefer the requested name; fall back to Dilithium* when required.
    candidates = [alg, _ML_DSA_FALLBACK.get(alg)]
    last_exc: Exception | None = None

    for cand in candidates:
        if not cand:
            continue  # pragma: no cover
        try:
            # IMPORTANT: do not swallow TypeError from Signature ctor — tests expect it to bubble.
            with mod.Signature(cand) as signer:  # type: ignore[attr-defined]
                pub = signer.generate_keypair()
                if not isinstance(pub, (bytes, bytearray)):
                    raise PQCBackendError("liboqs generate_keypair() did not return bytes public key")
                sec = _export_secret_key(signer)
                return bytes(pub), sec
        except TypeError:
            raise
        except Exception as e:
            # If liboqs does not recognize ML-DSA names, try the fallback mapping.
            last_exc = e
            continue

    raise PQCBackendError(f"liboqs could not create ML-DSA signer for {alg}") from last_exc


def generate_falcon_keypair(alg: str) -> Tuple[bytes, bytes]:
    if alg not in ALLOWED_FALCON_ALGS:
        raise PQCAlgorithmError(f"Falcon algorithm not allowed: {alg}")

    mod = _require_liboqs()
    with mod.Signature(alg) as signer:  # type: ignore[attr-defined]
        pub = signer.generate_keypair()
        if not isinstance(pub, (bytes, bytearray)):
            raise PQCBackendError("liboqs generate_keypair() did not return bytes public key")
        sec = _export_secret_key(signer)
        return bytes(pub), sec
