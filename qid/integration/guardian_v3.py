"""
MIT License
Copyright (c) 2026 DarekDGB

Guardian Wallet v3 auth bridge helpers for Q-ID.

Scope:
- Build a deterministic, fail-closed Guardian Wallet v3 request for Q-ID auth.
- Validate request shape strictly (schema-level only).
- Do NOT perform Guardian policy decisions.
- Do NOT perform cryptographic verification; caller must pass verified facts.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from ..canonical import canonical_json_bytes
from ..protocol import parse_login_request_uri
from .guardian import GuardianServiceConfig

_GW_COMPONENT = "guardian_wallet"
_GW_MODE = "qid_auth"
_GW_CONTRACT_VERSION = 3

_ALLOWED_TOP_LEVEL = {
    "contract_version",
    "component",
    "mode",
    "request_id",
    "wallet_ctx",
    "tx_ctx",
    "auth_ctx",
    "extra_signals",
}
_ALLOWED_AUTH_KEYS = {
    "qid_verified",
    "binding_verified",
    "service_id",
    "callback_url",
    "nonce",
    "address",
    "pubkey",
    "key_id",
    "require",
    "issued_at",
    "expires_at",
}
_ALLOWED_SIGNAL_KEYS = {
    "device_fingerprint",
    "sentinel_status",
    "geo_ip",
    "session",
    "trusted_device",
    "device_mismatch",
}
_ALLOWED_REQUIRE = {"legacy", "dual-proof"}


def _derived_request_id(auth_ctx: Dict[str, Any], extra_signals: Dict[str, Any]) -> str:
    payload = {
        "component": _GW_COMPONENT,
        "contract_version": _GW_CONTRACT_VERSION,
        "mode": _GW_MODE,
        "auth_ctx": auth_ctx,
        "extra_signals": extra_signals,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def build_guardian_v3_qid_auth_request(
    *,
    service: GuardianServiceConfig,
    login_uri: str,
    response_payload: Dict[str, Any],
    qid_verified: bool,
    binding_verified: Optional[bool] = None,
    extra_signals: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a Guardian Wallet v3 auth-mode request from verified Q-ID login facts.

    Fail-closed rules:
    - service_id/callback_url must match both the expected service and the login_uri
    - nonce must match the login_uri nonce
    - qid_verified is explicit and required (Guardian does not verify crypto)
    - no unknown signal keys
    """
    if not isinstance(login_uri, str) or not login_uri:
        raise TypeError("login_uri must be a non-empty string")
    if not isinstance(response_payload, dict):
        raise TypeError("response_payload must be a dict")
    if not isinstance(qid_verified, bool):
        raise TypeError("qid_verified must be a bool")
    if binding_verified is not None and not isinstance(binding_verified, bool):
        raise TypeError("binding_verified must be a bool when provided")
    if request_id is not None and (not isinstance(request_id, str) or not request_id.strip()):
        raise TypeError("request_id must be a non-empty string when provided")

    req = parse_login_request_uri(login_uri)
    if req.get("service_id") != service.service_id:
        raise TypeError("login_uri service_id does not match expected service")
    if req.get("callback_url") != service.callback_url:
        raise TypeError("login_uri callback_url does not match expected service")

    service_id = response_payload.get("service_id")
    nonce = response_payload.get("nonce")
    address = response_payload.get("address")
    pubkey = response_payload.get("pubkey")
    key_id = response_payload.get("key_id")
    require = response_payload.get("require")
    issued_at = response_payload.get("issued_at")
    expires_at = response_payload.get("expires_at")

    if not isinstance(service_id, str) or not service_id:
        raise TypeError("response_payload.service_id must be a non-empty string")
    if not isinstance(nonce, str) or not nonce:
        raise TypeError("response_payload.nonce must be a non-empty string")
    if not isinstance(address, str) or not address:
        raise TypeError("response_payload.address must be a non-empty string")
    if not isinstance(pubkey, str) or not pubkey:
        raise TypeError("response_payload.pubkey must be a non-empty string")
    if key_id is not None and (not isinstance(key_id, str) or not key_id):
        raise TypeError("response_payload.key_id must be a non-empty string when present")
    if require is not None:
        if not isinstance(require, str) or require not in _ALLOWED_REQUIRE:
            raise TypeError("response_payload.require must be 'legacy' or 'dual-proof' when present")
    if issued_at is not None and not isinstance(issued_at, int):
        raise TypeError("response_payload.issued_at must be an int when present")
    if expires_at is not None and not isinstance(expires_at, int):
        raise TypeError("response_payload.expires_at must be an int when present")
    if (issued_at is None) != (expires_at is None):
        raise TypeError("response_payload.issued_at/expires_at must be provided together")
    if issued_at is not None:
        if issued_at <= 0 or expires_at <= 0:
            raise ValueError("response_payload.issued_at/expires_at must be positive")
        if issued_at >= expires_at:
            raise ValueError("response_payload.expires_at must be greater than issued_at")

    if service_id != service.service_id:
        raise TypeError("response_payload.service_id mismatch vs expected service")
    if nonce != req.get("nonce"):
        raise TypeError("response_payload.nonce mismatch vs login_uri nonce")

    safe_signals = {} if extra_signals is None else dict(extra_signals)
    if not isinstance(safe_signals, dict):
        raise TypeError("extra_signals must be a dict when provided")
    unknown_signal_keys = set(safe_signals.keys()) - _ALLOWED_SIGNAL_KEYS
    if unknown_signal_keys:
        raise TypeError("extra_signals contains unknown keys")
    for key, value in safe_signals.items():
        if key in {"trusted_device", "device_mismatch"}:
            if not isinstance(value, bool):
                raise TypeError(f"extra_signals.{key} must be a bool")
        else:
            if not isinstance(value, str) or not value:
                raise TypeError(f"extra_signals.{key} must be a non-empty string")

    auth_ctx: Dict[str, Any] = {
        "qid_verified": qid_verified,
        "service_id": service_id,
        "callback_url": service.callback_url,
        "nonce": nonce,
        "address": address,
        "pubkey": pubkey,
    }
    if binding_verified is not None:
        auth_ctx["binding_verified"] = binding_verified
    if key_id is not None:
        auth_ctx["key_id"] = key_id
    if require is not None:
        auth_ctx["require"] = require
    if issued_at is not None and expires_at is not None:
        auth_ctx["issued_at"] = issued_at
        auth_ctx["expires_at"] = expires_at

    rid = request_id.strip() if isinstance(request_id, str) else _derived_request_id(auth_ctx, safe_signals)

    return {
        "contract_version": _GW_CONTRACT_VERSION,
        "component": _GW_COMPONENT,
        "mode": _GW_MODE,
        "request_id": rid,
        "wallet_ctx": {},
        "tx_ctx": {},
        "auth_ctx": auth_ctx,
        "extra_signals": safe_signals,
    }


def verify_guardian_v3_qid_auth_request(request: Any) -> bool:
    """Strict schema-level validation only. Returns False on invalid input."""
    if not isinstance(request, dict):
        return False
    if set(request.keys()) - _ALLOWED_TOP_LEVEL:
        return False
    if request.get("contract_version") != _GW_CONTRACT_VERSION:
        return False
    if request.get("component") != _GW_COMPONENT:
        return False
    if request.get("mode") != _GW_MODE:
        return False

    rid = request.get("request_id")
    if not isinstance(rid, str) or not rid:
        return False

    wallet_ctx = request.get("wallet_ctx")
    tx_ctx = request.get("tx_ctx")
    auth_ctx = request.get("auth_ctx")
    extra_signals = request.get("extra_signals")
    if not isinstance(wallet_ctx, dict) or wallet_ctx:
        return False
    if not isinstance(tx_ctx, dict) or tx_ctx:
        return False
    if not isinstance(auth_ctx, dict):
        return False
    if not isinstance(extra_signals, dict):
        return False

    if set(auth_ctx.keys()) - _ALLOWED_AUTH_KEYS:
        return False
    for key in ("qid_verified", "service_id", "callback_url", "nonce", "address", "pubkey"):
        if key not in auth_ctx:
            return False
    if not isinstance(auth_ctx.get("qid_verified"), bool):
        return False
    for key in ("service_id", "callback_url", "nonce", "address", "pubkey"):
        value = auth_ctx.get(key)
        if not isinstance(value, str) or not value:
            return False
    if "binding_verified" in auth_ctx and not isinstance(auth_ctx["binding_verified"], bool):
        return False
    if "key_id" in auth_ctx and (not isinstance(auth_ctx["key_id"], str) or not auth_ctx["key_id"]):
        return False
    if "require" in auth_ctx:
        value = auth_ctx["require"]
        if not isinstance(value, str) or value not in _ALLOWED_REQUIRE:
            return False
    if ("issued_at" in auth_ctx) != ("expires_at" in auth_ctx):
        return False
    if "issued_at" in auth_ctx:
        issued_at = auth_ctx["issued_at"]
        expires_at = auth_ctx["expires_at"]
        if not isinstance(issued_at, int) or not isinstance(expires_at, int):
            return False
        if issued_at <= 0 or expires_at <= 0 or issued_at >= expires_at:
            return False

    if set(extra_signals.keys()) - _ALLOWED_SIGNAL_KEYS:
        return False
    for key, value in extra_signals.items():
        if key in {"trusted_device", "device_mismatch"}:
            if not isinstance(value, bool):
                return False
        else:
            if not isinstance(value, str) or not value:
                return False

    return True
