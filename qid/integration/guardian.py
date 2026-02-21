"""
MIT License
Copyright (c) 2026 DarekDGB

Guardian rules integration helpers for Q-ID.

v1.0.0 scope:
- Provide a deterministic, fail-closed "event adapter" that a Guardian rules engine
  can consume.
- This module does NOT implement policy decisions (ALLOW/DENY). It only:
  - builds a Guardian-ready event from Q-ID login artifacts
  - validates that event shape strictly (fail-closed)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..protocol import parse_login_request_uri


@dataclass(frozen=True)
class GuardianServiceConfig:
    """
    Minimal relying-party config for Guardian event building.

    - service_id: stable identifier for the service
    - callback_url: HTTPS endpoint that receives Q-ID login responses
    """

    service_id: str
    callback_url: str


_GUARDIAN_EVENT_V = "1"
_GUARDIAN_EVENT_KIND = "qid_login_event_v1"

_ALLOWED_KEYS_BASE = {
    "v",
    "kind",
    "service_id",
    "callback_url",
    "nonce",
    "address",
    "pubkey",
    "key_id",
    "login_uri",
    "qid_signature",
}


def build_guardian_qid_login_event(
    *,
    service: GuardianServiceConfig,
    login_uri: str,
    response_payload: Dict[str, Any],
    qid_signature: Optional[str] = None,
    include_login_uri: bool = True,
) -> Dict[str, Any]:
    """
    Build a Guardian-consumable event for a Q-ID login.

    This is an ADAPTER ONLY:
    - It does not decide policy.
    - It does not perform cryptographic verification.
      (That remains the responsibility of the service/backend.)
    - It is strict and deterministic: missing/wrong-typed fields raise TypeError.

    The event is safe to feed into Guardian as a stable "facts bundle".
    """
    if not isinstance(login_uri, str) or not login_uri:
        raise TypeError("login_uri must be a non-empty string")
    if not isinstance(response_payload, dict):
        raise TypeError("response_payload must be a dict")
    if qid_signature is not None and (not isinstance(qid_signature, str) or not qid_signature):
        raise TypeError("qid_signature must be a non-empty string when provided")

    req = parse_login_request_uri(login_uri)

    # Fail-closed: ensure wallet wasn't tricked into signing for wrong RP.
    if req.get("service_id") != service.service_id:
        raise TypeError("login_uri service_id does not match expected service")
    if req.get("callback_url") != service.callback_url:
        raise TypeError("login_uri callback_url does not match expected service")

    service_id = response_payload.get("service_id")
    nonce = response_payload.get("nonce")
    address = response_payload.get("address")
    pubkey = response_payload.get("pubkey")
    key_id = response_payload.get("key_id")

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

    # Fail-closed: response must bind to the same RP + callback.
    if service_id != service.service_id:
        raise TypeError("response_payload.service_id mismatch vs expected service")
    if nonce != req.get("nonce"):
        # Nonce in response must bind to nonce in request URI payload.
        raise TypeError("response_payload.nonce mismatch vs login_uri nonce")

    ev: Dict[str, Any] = {
        "v": _GUARDIAN_EVENT_V,
        "kind": _GUARDIAN_EVENT_KIND,
        "service_id": service.service_id,
        "callback_url": service.callback_url,
        "nonce": nonce,
        "address": address,
        "pubkey": pubkey,
    }

    if key_id is not None:
        ev["key_id"] = key_id
    if include_login_uri:
        ev["login_uri"] = login_uri
    if qid_signature is not None:
        ev["qid_signature"] = qid_signature

    return ev


def verify_guardian_qid_login_event(event: Any) -> bool:
    """
    Strict validation of the Guardian event shape.

    This is *schema-level* validation only (types/required/const/allowlist).
    Crypto verification remains outside Guardian adapter.
    """
    if not isinstance(event, dict):
        return False

    # deny-by-default: no unexpected keys
    for k in event.keys():
        if k not in _ALLOWED_KEYS_BASE:
            return False

    if event.get("v") != _GUARDIAN_EVENT_V:
        return False
    if event.get("kind") != _GUARDIAN_EVENT_KIND:
        return False

    # required fields
    for k in ("service_id", "callback_url", "nonce", "address", "pubkey"):
        v = event.get(k)
        if not isinstance(v, str) or not v:
            return False

    # optional fields
    key_id = event.get("key_id")
    if key_id is not None and (not isinstance(key_id, str) or not key_id):
        return False

    login_uri = event.get("login_uri")
    if login_uri is not None and (not isinstance(login_uri, str) or not login_uri):
        return False

    qid_signature = event.get("qid_signature")
    if qid_signature is not None and (not isinstance(qid_signature, str) or not qid_signature):
        return False

    return True
