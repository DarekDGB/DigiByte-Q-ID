"""
Crypto helpers for DigiByte Q-ID.

This module provides a **development-focused** cryptographic layer for Q-ID.

It is intentionally simple and self-contained so it can run everywhere
(including GitHub Actions and an iPhone-only workflow) while exposing the
same interfaces that a future PQC implementation will use.

Production deployments are expected to replace the internals with real
post-quantum / hybrid algorithms, keeping function signatures stable.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any, Dict


# ---------------------------------------------------------------------------
# Algorithms
# ---------------------------------------------------------------------------

# Development algorithm (current default)
DEV_ALGO = "dev-hmac-sha256"

# Planned post-quantum / hybrid algorithms.
# These are **stubbed** in this reference implementation – they behave
# like distinct algorithms but internally still use HMAC so tests can run
# in very simple environments.
ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "hybrid-dev-ml-dsa"


@dataclass
class QIDKeyPair:
    """
    Minimal key-pair structure for Q-ID.

    - ``algorithm``: which crypto backend produced this key.
    - ``secret_key``: base64-encoded secret / private key bytes.
    - ``public_key``: base64-encoded public identifier.
    """
    algorithm: str
    secret_key: str
    public_key: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _canonical_json(data: Dict[str, Any]) -> bytes:
    """
    Serialize a payload into canonical JSON bytes.

    - Keys sorted
    - No extra whitespace
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def generate_keypair(algorithm: str = DEV_ALGO) -> QIDKeyPair:
    """
    Generate a Q-ID key-pair for the given algorithm.

    This keeps the interface stable so that real PQC implementations can
    drop in later without changing callers.
    """
    if algorithm == DEV_ALGO:
        # 32-byte dev secret.
        secret = secrets.token_bytes(32)
    elif algorithm in (ML_DSA_ALGO, FALCON_ALGO):
        # Simulate "larger" PQC-style keys.
        secret = secrets.token_bytes(64)
    elif algorithm == HYBRID_ALGO:
        # Simulate a hybrid key (two 32-byte halves).
        secret = secrets.token_bytes(64)
    else:
        raise ValueError(f"Unknown Q-ID algorithm: {algorithm!r}")

    pub = hashlib.sha256(secret).digest()
    return QIDKeyPair(
        algorithm=algorithm,
        secret_key=_b64encode(secret),
        public_key=_b64encode(pub),
    )


def generate_dev_keypair() -> QIDKeyPair:
    """
    Convenience wrapper for the dev backend.

    Existing tests and examples use this function.
    """
    return generate_keypair(DEV_ALGO)


# ---------------------------------------------------------------------------
# Signing & verification
# ---------------------------------------------------------------------------


def sign_payload(payload: Dict[str, Any], keypair: QIDKeyPair) -> str:
    """
    Sign a payload with the given key-pair.

    Current behaviour (reference implementation):

    - All algorithms are implemented using HMAC over canonical JSON so
      they can run in environments without PQC libraries.
    - Each algorithm uses a slightly different construction so that
      signatures are not interchangeable between backends.

    Callers should treat the result as an opaque base64 string.
    """
    msg = _canonical_json(payload)
    secret = _b64decode(keypair.secret_key)

    if keypair.algorithm == DEV_ALGO:
        # HMAC-SHA256
        sig = hmac.new(secret, msg, hashlib.sha256).digest()
        return _b64encode(sig)

    if keypair.algorithm in (ML_DSA_ALGO, FALCON_ALGO):
        # PQC stubs: HMAC-SHA512 with an algorithm prefix.
        core_sig = hmac.new(secret, msg, hashlib.sha512).digest()
        combined = keypair.algorithm.encode("ascii") + b":" + core_sig
        return _b64encode(combined)

    if keypair.algorithm == HYBRID_ALGO:
        # Hybrid stub: split the secret into two halves and sign with
        # two different hash functions, then concatenate.
        if len(secret) < 64:
            raise ValueError("Hybrid secret key must be at least 64 bytes")

        s1, s2 = secret[:32], secret[32:64]
        sig1 = hmac.new(s1, msg, hashlib.sha256).digest()
        sig2 = hmac.new(s2, msg, hashlib.sha512).digest()
        combined = sig1 + sig2
        return _b64encode(combined)

    raise ValueError(f"Unsupported algorithm for signing: {keypair.algorithm!r}")


def verify_payload(payload: Dict[str, Any], signature: str, keypair: QIDKeyPair) -> bool:
    """
    Verify a signature over a payload using the given key-pair.

    In a real public-key design this would only require the public key,
    but for the dev/HMAC-based stubs we re-use the secret key.
    """
    msg = _canonical_json(payload)
    secret = _b64decode(keypair.secret_key)

    try:
        sig_bytes = _b64decode(signature)
    except Exception:
        return False

    if keypair.algorithm == DEV_ALGO:
        expected = hmac.new(secret, msg, hashlib.sha256).digest()
        return hmac.compare_digest(expected, sig_bytes)

    if keypair.algorithm in (ML_DSA_ALGO, FALCON_ALGO):
        prefix = keypair.algorithm.encode("ascii") + b":"
        if not sig_bytes.startswith(prefix):
            return False

        core_sig = sig_bytes[len(prefix):]
        expected_core = hmac.new(secret, msg, hashlib.sha512).digest()
        return hmac.compare_digest(expected_core, core_sig)

    if keypair.algorithm == HYBRID_ALGO:
        if len(secret) < 64:
            return False

        s1, s2 = secret[:32], secret[32:64]
        expected1 = hmac.new(s1, msg, hashlib.sha256).digest()
        expected2 = hmac.new(s2, msg, hashlib.sha512).digest()
        expected = expected1 + expected2
        return hmac.compare_digest(expected, sig_bytes)

    raise ValueError(f"Unsupported algorithm for verification: {keypair.algorithm!r}")
