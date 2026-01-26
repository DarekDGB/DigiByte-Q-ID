"""Fail-closed PQC verification for Q-ID login binding."""

from __future__ import annotations

from typing import Any, Mapping
import base64

from qid.pqc_backends import (
    FALCON_ALGO,
    HYBRID_ALGO,
    ML_DSA_ALGO,
    enforce_no_silent_fallback_for_alg,
    liboqs_verify,
    selected_backend,
)

# ✅ Keep canonicalization single-source-of-truth (already used by signing)
from qid.pqc_sign import canonical_payload_bytes  # re-export for tests


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _payload_for_pqc(src: Mapping[str, Any]) -> dict[str, Any]:
    """
    Coverage contract:
    remove algorithm tag and any signature fields from a payload copy
    """
    d = dict(src)
    d.pop("pqc_alg", None)
    d.pop("pqc_sig", None)
    d.pop("pqc_sig_ml_dsa", None)
    d.pop("pqc_sig_falcon", None)
    return d


def _binding_payload(binding_env: Mapping[str, Any]) -> Mapping[str, Any]:
    p = binding_env.get("payload")
    if not isinstance(p, Mapping):
        raise ValueError("binding_env.payload missing")
    return p


def verify_pqc_login(*args: Any, **kwargs: Any) -> bool:
    """
    Accept BOTH call styles used in your tests:
      1) verify_pqc_login(login_payload=..., binding_env=...)
      2) verify_pqc_login(binding_payload, login_payload)  (dual-proof tests)
    Always fail-closed: return False on any error.
    """
    try:
        if "login_payload" in kwargs or "binding_env" in kwargs:
            login_payload = kwargs.get("login_payload")
            binding_env = kwargs.get("binding_env")
            if not isinstance(login_payload, Mapping) or not isinstance(binding_env, Mapping):
                return False
            binding_payload = _binding_payload(binding_env)
        else:
            if len(args) != 2:
                return False
            binding_payload, login_payload = args
            if not isinstance(binding_payload, Mapping) or not isinstance(login_payload, Mapping):
                return False

        backend = selected_backend()
        if backend != "liboqs":
            return False

        alg = login_payload.get("pqc_alg")
        if not isinstance(alg, str) or not alg:
            return False

        # Guardrail (no silent fallback when backend selected)
        enforce_no_silent_fallback_for_alg(alg)

        # Optional consistency check if response includes pqc_payload
        resp_payload = login_payload.get("pqc_payload")
        if isinstance(resp_payload, Mapping) and dict(resp_payload) != dict(binding_payload):
            return False

        msg = canonical_payload_bytes(binding_payload)

        pubkeys = binding_payload.get("pqc_pubkeys")
        if not isinstance(pubkeys, Mapping):
            return False

        policy = binding_payload.get("policy")
        if not isinstance(policy, str) or not policy:
            return False

        if alg == ML_DSA_ALGO:
            if policy not in {"ml-dsa", "hybrid"}:
                return False
            sig_b64u = login_payload.get("pqc_sig")
            pub_b64u = pubkeys.get("ml_dsa")
            if not isinstance(sig_b64u, str) or not isinstance(pub_b64u, str):
                return False
            return bool(liboqs_verify(ML_DSA_ALGO, msg, _b64u_decode(sig_b64u), _b64u_decode(pub_b64u)))

        if alg == FALCON_ALGO:
            if policy not in {"falcon", "hybrid"}:
                return False
            sig_b64u = login_payload.get("pqc_sig")
            pub_b64u = pubkeys.get("falcon")
            if not isinstance(sig_b64u, str) or not isinstance(pub_b64u, str):
                return False
            return bool(liboqs_verify(FALCON_ALGO, msg, _b64u_decode(sig_b64u), _b64u_decode(pub_b64u)))

        if alg == HYBRID_ALGO:
            if policy != "hybrid":
                return False

            sig_ml = login_payload.get("pqc_sig_ml_dsa")
            sig_fa = login_payload.get("pqc_sig_falcon")

            # dual-proof tests also allow nested dict: pqc_sig: {ml_dsa, falcon}
            if (not isinstance(sig_ml, str)) or (not isinstance(sig_fa, str)):
                nested = login_payload.get("pqc_sig")
                if isinstance(nested, Mapping):
                    sig_ml = nested.get("ml_dsa")
                    sig_fa = nested.get("falcon")

            pub_ml = pubkeys.get("ml_dsa")
            pub_fa = pubkeys.get("falcon")

            if not all(isinstance(x, str) for x in [sig_ml, sig_fa, pub_ml, pub_fa]):
                return False

            ok_ml = bool(liboqs_verify(ML_DSA_ALGO, msg, _b64u_decode(sig_ml), _b64u_decode(pub_ml)))
            ok_fa = bool(liboqs_verify(FALCON_ALGO, msg, _b64u_decode(sig_fa), _b64u_decode(pub_fa)))
            return bool(ok_ml and ok_fa)

        return False
    except Exception:
        return False
