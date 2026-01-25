from __future__ import annotations

"""
PQC verify helpers for DigiByte Q-ID.

This module MUST match the test contract used by:
tests/test_dual_proof_login_real_liboqs_optional.py

Contract (as tests use it):
- verify_pqc_login(binding_payload, response_dict) -> bool
- binding_payload contains:
    - policy: "ml-dsa" | "falcon" | "hybrid"
    - pqc_pubkeys: {"ml_dsa": <b64u>|None, "falcon": <b64u>|None}
- response_dict contains:
    - pqc_payload: the same payload that was signed (usually equals binding_payload)
    - pqc_alg: "pqc-ml-dsa" | "pqc-falcon" | "pqc-hybrid-ml-dsa-falcon"
    - pqc_sig:
        - str (b64u) for single-alg
        - {"ml_dsa": <b64u>, "falcon": <b64u>} for hybrid

Fail-closed: returns False for any malformed input or backend error.
No silent fallback: if backend selected, enforce wiring for the algorithm.
"""

import base64
import json
from typing import Any, Mapping

from .pqc_backends import (
    ML_DSA_ALGO,
    FALCON_ALGO,
    HYBRID_ALGO,
    PQCBackendError,
    enforce_no_silent_fallback_for_alg,
    liboqs_verify,
    selected_backend,
)


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    # Must match signing side deterministically (tests sign canonical_payload_bytes(request))
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _get_mapping(d: Any) -> Mapping[str, Any] | None:
    return d if isinstance(d, Mapping) else None


def _get_str(d: Mapping[str, Any], k: str) -> str | None:
    v = d.get(k)
    return v if isinstance(v, str) and v else None


def _decode_required_b64u(s: Any) -> bytes:
    if not isinstance(s, str) or not s:
        raise ValueError("missing b64u")
    return _b64url_decode(s)


def verify_pqc_login(binding_payload: Mapping[str, Any], response: Mapping[str, Any]) -> bool:
    """
    Verify PQC signature(s) over the binding payload.

    NOTE: Must accept positional args (tests call it positionally).
    """
    try:
        # Backend must be explicitly selected to verify PQC.
        if selected_backend() is None:
            return False

        payload = _get_mapping(binding_payload)
        resp = _get_mapping(response)
        if payload is None or resp is None:
            return False

        # Response must include pqc_payload; tests set it to request.
        resp_payload = _get_mapping(resp.get("pqc_payload"))
        if resp_payload is None:
            return False

        # Verify uses the payload that was signed (response side),
        # but we also require it matches the provided binding_payload for safety.
        if dict(resp_payload) != dict(payload):
            return False

        alg = _get_str(resp, "pqc_alg")
        if alg not in {ML_DSA_ALGO, FALCON_ALGO, HYBRID_ALGO}:
            return False

        enforce_no_silent_fallback_for_alg(alg)

        policy = _get_str(payload, "policy")
        pubkeys = _get_mapping(payload.get("pqc_pubkeys"))
        if policy not in {"ml-dsa", "falcon", "hybrid"} or pubkeys is None:
            return False

        msg = canonical_payload_bytes(resp_payload)

        if alg == ML_DSA_ALGO:
            if policy != "ml-dsa":
                return False
            pub_b = _decode_required_b64u(pubkeys.get("ml_dsa"))
            sig_b = _decode_required_b64u(resp.get("pqc_sig"))
            return bool(liboqs_verify(ML_DSA_ALGO, msg, sig_b, pub_b))

        if alg == FALCON_ALGO:
            if policy != "falcon":
                return False
            pub_b = _decode_required_b64u(pubkeys.get("falcon"))
            sig_b = _decode_required_b64u(resp.get("pqc_sig"))
            return bool(liboqs_verify(FALCON_ALGO, msg, sig_b, pub_b))

        # Hybrid
        if policy != "hybrid":
            return False

        sig_obj = _get_mapping(resp.get("pqc_sig"))
        if sig_obj is None:
            return False

        pub_ml = _decode_required_b64u(pubkeys.get("ml_dsa"))
        pub_fa = _decode_required_b64u(pubkeys.get("falcon"))
        sig_ml = _decode_required_b64u(sig_obj.get("ml_dsa"))
        sig_fa = _decode_required_b64u(sig_obj.get("falcon"))

        return bool(
            liboqs_verify(ML_DSA_ALGO, msg, sig_ml, pub_ml)
            and liboqs_verify(FALCON_ALGO, msg, sig_fa, pub_fa)
        )

    except (ValueError, TypeError, PQCBackendError):
        return False
    except Exception:
        return False
