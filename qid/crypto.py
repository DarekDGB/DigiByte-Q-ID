"""
Crypto helpers for DigiByte Q-ID.

This module provides a **development-focused** cryptographic layer for Q-ID.

Key contract goals (authoritative):
- Deterministic signing input: canonical JSON bytes only.
- Algorithm IDs are explicit and stable.
- Signature format is an explicit envelope (v1), fail-closed.
- No silent fallback or downgrade.
- Hybrid signatures are strict AND: both ML-DSA and Falcon must verify.
- If a real PQC backend is explicitly selected, we MUST use it for PQC algs
  (no stub fallback).

This reference implementation uses HMAC-based stubs so it runs everywhere
(GitHub Actions + iPhone-only workflow). Real PQC backends are optional and
only used when QID_PQC_BACKEND is set.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Mapping


# ---------------------------------------------------------------------------
# Algorithm IDs (protocol-visible)
# ---------------------------------------------------------------------------

DEV_ALGO = "dev-hmac-sha256"

ML_DSA_ALGO = "pqc-ml-dsa"  # CRYSTALS-Dilithium (NIST ML-DSA / FIPS 204)
FALCON_ALGO = "pqc-falcon"  # Falcon
HYBRID_ALGO = "pqc-hybrid-ml-dsa-falcon"  # strict hybrid (AND)

_LEGACY_HYBRID_ALGO = "hybrid-dev-ml-dsa"

_ALLOWED_ALGOS = {DEV_ALGO, ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO, _LEGACY_HYBRID_ALGO}

_SIG_ENVELOPE_VERSION = 1


@dataclass(frozen=True)
class QIDKeyPair:
    """
    Minimal key-pair structure for Q-ID.

    secret_key/public_key encoding rules:

    - DEV + stub PQC:
        secret_key = base64(raw bytes)
        public_key = base64(sha256(secret))
    - Real liboqs PQC (when QID_PQC_BACKEND=liboqs):
        secret_key = base64(liboqs secret key bytes)
        public_key = base64(liboqs public key bytes)
    - HYBRID:
        secret_key = base64(canonical_json({"pqc-ml-dsa":"<b64bytes>","pqc-falcon":"<b64bytes>"}))
        public_key = base64(canonical_json({"pqc-ml-dsa":"<b64bytes>","pqc-falcon":"<b64bytes>"}))
    """

    algorithm: str
    secret_key: str
    public_key: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _canonical_json(data: Mapping[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _envelope_encode(obj: Dict[str, Any]) -> str:
    raw = _canonical_json(obj)
    return _b64encode(raw)


def _envelope_decode(sig: str) -> Dict[str, Any] | None:
    try:
        raw = _b64decode(sig)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            return None
        return data
    except Exception:
        return None


def _normalize_alg(alg: str) -> str:
    if alg == _LEGACY_HYBRID_ALGO:
        return HYBRID_ALGO
    return alg


def _selected_backend() -> str | None:
    try:
        from qid.pqc_backends import selected_backend
    except Exception:
        return None
    return selected_backend()


def _enforce_no_silent_fallback(alg: str) -> None:
    """
    Backend selection validation. Routing to real backend is enforced below.
    """
    try:
        from qid.pqc_backends import enforce_no_silent_fallback_for_alg
    except Exception:
        return
    enforce_no_silent_fallback_for_alg(alg)


def _decode_hybrid_key_b64_json(b64_json: str) -> Dict[str, bytes] | None:
    """
    Decode base64(canonical_json({alg: b64(keybytes), ...})) into {alg: keybytes}.
    Fail-closed: returns None on any failure.
    """
    try:
        raw = _b64decode(b64_json)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            return None
        out: Dict[str, bytes] = {}
        for k in (ML_DSA_ALGO, FALCON_ALGO):
            v = data.get(k)
            if not isinstance(v, str):
                return None
            out[k] = _b64decode(v)
        # Strict: only two keys
        if set(data.keys()) != {ML_DSA_ALGO, FALCON_ALGO}:
            return None
        return out
    except Exception:
        return None


def _encode_hybrid_key_b64_json(keys: Dict[str, bytes]) -> str:
    obj = {k: _b64encode(v) for k, v in keys.items()}
    raw = _canonical_json(obj)
    return _b64encode(raw)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair(algorithm: str = DEV_ALGO) -> QIDKeyPair:
    if algorithm not in _ALLOWED_ALGOS:
        raise ValueError(f"Unknown Q-ID algorithm: {algorithm!r}")

    alg = _normalize_alg(algorithm)
    backend = _selected_backend()

    # Real PQC keygen only when explicitly selected.
    if backend == "liboqs" and alg in (ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO):
        from qid.pqc_backends import PQCBackendError, liboqs_generate_keypair

        if alg in (ML_DSA_ALGO, FALCON_ALGO):
            pub, sec = liboqs_generate_keypair(alg)
            return QIDKeyPair(algorithm=alg, secret_key=_b64encode(sec), public_key=_b64encode(pub))

        # HYBRID: generate both, store as base64(json)
        pub_ml, sec_ml = liboqs_generate_keypair(ML_DSA_ALGO)
        pub_fa, sec_fa = liboqs_generate_keypair(FALCON_ALGO)

        sec_map = {ML_DSA_ALGO: sec_ml, FALCON_ALGO: sec_fa}
        pub_map = {ML_DSA_ALGO: pub_ml, FALCON_ALGO: pub_fa}

        return QIDKeyPair(
            algorithm=HYBRID_ALGO,
            secret_key=_encode_hybrid_key_b64_json(sec_map),
            public_key=_encode_hybrid_key_b64_json(pub_map),
        )

    # Default: stub keys (CI-safe)
    if alg == DEV_ALGO:
        secret = secrets.token_bytes(32)
    elif alg in (ML_DSA_ALGO, FALCON_ALGO):
        secret = secrets.token_bytes(64)
    elif alg == HYBRID_ALGO:
        secret = secrets.token_bytes(64)
    else:
        raise ValueError(f"Unsupported Q-ID algorithm: {algorithm!r}")

    pub = hashlib.sha256(secret).digest()
    return QIDKeyPair(algorithm=alg, secret_key=_b64encode(secret), public_key=_b64encode(pub))


def generate_dev_keypair() -> QIDKeyPair:
    return generate_keypair(DEV_ALGO)


# ---------------------------------------------------------------------------
# Backend stubs (dev/HMAC only)
# ---------------------------------------------------------------------------

def _stub_sign_dev(msg: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, msg, hashlib.sha256).digest()


def _stub_verify_dev(msg: bytes, secret: bytes, sig: bytes) -> bool:
    expected = hmac.new(secret, msg, hashlib.sha256).digest()
    return hmac.compare_digest(expected, sig)


def _stub_sign_pqc(msg: bytes, secret: bytes, alg: str) -> bytes:
    core = hmac.new(secret, msg, hashlib.sha512).digest()
    return alg.encode("ascii") + b":" + core


def _stub_verify_pqc(msg: bytes, secret: bytes, sig: bytes, alg: str) -> bool:
    prefix = alg.encode("ascii") + b":"
    if not sig.startswith(prefix):
        return False
    core = sig[len(prefix) :]
    expected = hmac.new(secret, msg, hashlib.sha512).digest()
    return hmac.compare_digest(expected, core)


def _stub_sign_hybrid(msg: bytes, secret: bytes) -> Dict[str, bytes]:
    if len(secret) < 64:
        raise ValueError("Hybrid secret key must be at least 64 bytes")
    s1, s2 = secret[:32], secret[32:64]
    return {
        ML_DSA_ALGO: hmac.new(s1, msg, hashlib.sha256).digest(),
        FALCON_ALGO: hmac.new(s2, msg, hashlib.sha512).digest(),
    }


def _stub_verify_hybrid(msg: bytes, secret: bytes, sigs: Mapping[str, bytes]) -> bool:
    if len(secret) < 64:
        return False
    if set(sigs.keys()) != {ML_DSA_ALGO, FALCON_ALGO}:
        return False
    s1, s2 = secret[:32], secret[32:64]
    exp_ml = hmac.new(s1, msg, hashlib.sha256).digest()
    exp_fa = hmac.new(s2, msg, hashlib.sha512).digest()
    return hmac.compare_digest(exp_ml, sigs[ML_DSA_ALGO]) and hmac.compare_digest(exp_fa, sigs[FALCON_ALGO])


# ---------------------------------------------------------------------------
# Signing & verification (public API)
# ---------------------------------------------------------------------------

def sign_payload(payload: Dict[str, Any], keypair: QIDKeyPair) -> str:
    alg = _normalize_alg(keypair.algorithm)
    if alg not in _ALLOWED_ALGOS:
        raise ValueError(f"Unknown Q-ID algorithm: {keypair.algorithm!r}")

    _enforce_no_silent_fallback(alg)

    msg = _canonical_json(payload)
    backend = _selected_backend()

    # Real liboqs signing (no stub fallback)
    if backend == "liboqs" and alg in (ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO):
        from qid.pqc_backends import liboqs_sign

        if alg in (ML_DSA_ALGO, FALCON_ALGO):
            sec = _b64decode(keypair.secret_key)
            sig = liboqs_sign(alg, msg, sec)
            env = {"v": _SIG_ENVELOPE_VERSION, "alg": alg, "sig": _b64encode(sig)}
            return _envelope_encode(env)

        # HYBRID
        sec_map = _decode_hybrid_key_b64_json(keypair.secret_key)
        if sec_map is None:
            raise ValueError("Invalid hybrid secret_key encoding")

        sig_ml = liboqs_sign(ML_DSA_ALGO, msg, sec_map[ML_DSA_ALGO])
        sig_fa = liboqs_sign(FALCON_ALGO, msg, sec_map[FALCON_ALGO])

        env = {
            "v": _SIG_ENVELOPE_VERSION,
            "alg": HYBRID_ALGO,
            "sigs": {ML_DSA_ALGO: _b64encode(sig_ml), FALCON_ALGO: _b64encode(sig_fa)},
        }
        return _envelope_encode(env)

    # Default stub signing
    secret = _b64decode(keypair.secret_key)

    if alg == DEV_ALGO:
        sig = _stub_sign_dev(msg, secret)
        return _envelope_encode({"v": _SIG_ENVELOPE_VERSION, "alg": DEV_ALGO, "sig": _b64encode(sig)})

    if alg in (ML_DSA_ALGO, FALCON_ALGO):
        sig = _stub_sign_pqc(msg, secret, alg)
        return _envelope_encode({"v": _SIG_ENVELOPE_VERSION, "alg": alg, "sig": _b64encode(sig)})

    if alg == HYBRID_ALGO:
        sigs = _stub_sign_hybrid(msg, secret)
        env = {"v": _SIG_ENVELOPE_VERSION, "alg": HYBRID_ALGO, "sigs": {k: _b64encode(v) for k, v in sigs.items()}}
        return _envelope_encode(env)

    raise ValueError(f"Unsupported algorithm for signing: {keypair.algorithm!r}")


def verify_payload(payload: Dict[str, Any], signature: str, keypair: QIDKeyPair) -> bool:
    env = _envelope_decode(signature)
    if env is None:
        return False
    if env.get("v") != _SIG_ENVELOPE_VERSION:
        return False

    env_alg = env.get("alg")
    if not isinstance(env_alg, str):
        return False
    env_alg = _normalize_alg(env_alg)

    kp_alg = _normalize_alg(keypair.algorithm)
    if env_alg != kp_alg:
        return False
    if env_alg not in _ALLOWED_ALGOS:
        return False

    _enforce_no_silent_fallback(env_alg)

    msg = _canonical_json(payload)
    backend = _selected_backend()

    # Real liboqs verification (no stub fallback)
    if backend == "liboqs" and env_alg in (ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO):
        from qid.pqc_backends import liboqs_verify

        if env_alg in (ML_DSA_ALGO, FALCON_ALGO):
            sig_b64 = env.get("sig")
            if not isinstance(sig_b64, str):
                return False
            try:
                sig_bytes = _b64decode(sig_b64)
            except Exception:
                return False
            pub = _b64decode(keypair.public_key)
            return liboqs_verify(env_alg, msg, sig_bytes, pub)

        # HYBRID (strict AND)
        sigs = env.get("sigs")
        if not isinstance(sigs, dict):
            return False
        if set(sigs.keys()) != {ML_DSA_ALGO, FALCON_ALGO}:
            return False

        pub_map = _decode_hybrid_key_b64_json(keypair.public_key)
        if pub_map is None:
            return False

        try:
            sig_ml = _b64decode(sigs[ML_DSA_ALGO])
            sig_fa = _b64decode(sigs[FALCON_ALGO])
        except Exception:
            return False

        ok_ml = liboqs_verify(ML_DSA_ALGO, msg, sig_ml, pub_map[ML_DSA_ALGO])
        ok_fa = liboqs_verify(FALCON_ALGO, msg, sig_fa, pub_map[FALCON_ALGO])
        return bool(ok_ml and ok_fa)

    # Default stub verification
    secret = _b64decode(keypair.secret_key)

    if env_alg in (DEV_ALGO, ML_DSA_ALGO, FALCON_ALGO):
        sig_b64 = env.get("sig")
        if not isinstance(sig_b64, str):
            return False
        try:
            sig_bytes = _b64decode(sig_b64)
        except Exception:
            return False
        if env_alg == DEV_ALGO:
            return _stub_verify_dev(msg, secret, sig_bytes)
        return _stub_verify_pqc(msg, secret, sig_bytes, env_alg)

    if env_alg == HYBRID_ALGO:
        sigs = env.get("sigs")
        if not isinstance(sigs, dict):
            return False
        if set(sigs.keys()) != {ML_DSA_ALGO, FALCON_ALGO}:
            return False

        decoded: Dict[str, bytes] = {}
        for k in (ML_DSA_ALGO, FALCON_ALGO):
            v = sigs.get(k)
            if not isinstance(v, str):
                return False
            try:
                decoded[k] = _b64decode(v)
            except Exception:
                return False

        return _stub_verify_hybrid(msg, secret, decoded)

    return False
