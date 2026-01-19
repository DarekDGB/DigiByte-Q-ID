"""
High-level DigiByte Q-ID protocol helpers.

This module provides helpers for:

- Login request:
    - build_login_request_payload(...)
    - build_login_request_uri(...)
    - parse_login_request_uri(...)

- Registration request:
    - build_registration_payload(...)
    - build_registration_uri(...)
    - parse_registration_uri(...)

- Signed login response:
    - build_login_response_payload(...)
    - sign_login_response(...)
    - verify_login_response(...)
    - server_verify_login_response(...)

These helpers focus on shaping JSON payloads and wrapping/unwrapping
them into simple qid:// URIs. Cryptography, signatures, storage and
policy checks will be added later.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict

from .crypto import QIDKeyPair, sign_payload, verify_payload
from .qr_payloads import decode_login_request, encode_login_request


# ---------------------------------------------------------------------------
# Shared base64url helpers (local to this module)
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(token: str) -> bytes:
    """Decode URL-safe base64 without padding."""
    padding = "=" * (-len(token) % 4)
    return base64.urlsafe_b64decode(token + padding)


# ---------------------------------------------------------------------------
# Login helpers
# ---------------------------------------------------------------------------


def build_login_request_payload(
    service_id: str,
    nonce: str,
    callback_url: str,
    version: str = "1",
) -> Dict[str, Any]:
    """
    Build a minimal Q-ID login request payload.

    This does *not* handle crypto or signatures. It only shapes the JSON
    that will be embedded into the qid:// URI.
    """
    return {
        "type": "login_request",
        "service_id": service_id,
        "nonce": nonce,
        "callback_url": callback_url,
        "version": version,
    }


def build_login_request_uri(payload: Dict[str, Any]) -> str:
    """
    Convert a login payload into a qid:// URI using the QR encoder.
    """
    return encode_login_request(payload)


def parse_login_request_uri(uri: str) -> Dict[str, Any]:
    """
    Decode a qid://login URI back into a login payload dictionary.
    """
    return decode_login_request(uri)


# ---------------------------------------------------------------------------
# Signed login response helpers
# ---------------------------------------------------------------------------


def build_login_response_payload(
    request_payload: Dict[str, Any],
    address: str,
    pubkey: str,
    key_id: str | None = None,
    version: str = "1",
) -> Dict[str, Any]:
    """
    Build a Q-ID login response payload that a wallet would sign.

    Mirrors the service_id and nonce from the login request and attaches the
    wallet's address + public key information.
    """
    service_id = request_payload.get("service_id")
    nonce = request_payload.get("nonce")

    if not service_id or not nonce:
        raise ValueError("Login request payload must contain 'service_id' and 'nonce'.")

    payload: Dict[str, Any] = {
        "type": "login_response",
        "service_id": service_id,
        "nonce": nonce,
        "address": address,
        "pubkey": pubkey,
        "version": version,
    }
    if key_id is not None:
        payload["key_id"] = key_id
    return payload


def sign_login_response(payload: Dict[str, Any], keypair: QIDKeyPair) -> str:
    """
    Sign a login response payload.

    Delegates to qid.crypto.sign_payload(). Production will swap in real
    ML-DSA/Falcon/hybrid behind the same API.
    """
    return sign_payload(payload, keypair)


def verify_login_response(payload: Dict[str, Any], signature: str, keypair: QIDKeyPair) -> bool:
    """
    Verify a signed login response payload.

    NOTE: In dev backend, verification uses the same symmetric key.
    Real PQC will verify with public key only.
    """
    return verify_payload(payload, signature, keypair)


def server_verify_login_response(
    request_payload: Dict[str, Any],
    response_payload: Dict[str, Any],
    signature: str,
    keypair: QIDKeyPair,
) -> bool:
    """
    Reference server-side verification flow for a signed login response.

    Performs:
    - shape check (type)
    - service_id/nonce match request<->response
    - cryptographic verification
    """
    if response_payload.get("type") != "login_response":
        return False

    if response_payload.get("service_id") != request_payload.get("service_id"):
        return False
    if response_payload.get("nonce") != request_payload.get("nonce"):
        return False

    return verify_login_response(response_payload, signature, keypair)


# ---------------------------------------------------------------------------
# Registration helpers
# ---------------------------------------------------------------------------


def build_registration_payload(
    service_id: str,
    address: str,
    pubkey: str,
    nonce: str,
    callback_url: str,
    version: str = "1",
) -> Dict[str, Any]:
    """
    Build a Q-ID registration payload.
    """
    return {
        "type": "registration",
        "service_id": service_id,
        "address": address,
        "pubkey": pubkey,
        "nonce": nonce,
        "callback_url": callback_url,
        "version": version,
    }


def build_registration_uri(payload: Dict[str, Any]) -> str:
    """
    Encode a registration payload into a qid://register URI.

    Format:
        qid://register?d=<base64url(JSON)>
    """
    json_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    token = _b64url_encode(json_str.encode("utf-8"))
    return f"qid://register?d={token}"


def parse_registration_uri(uri: str) -> Dict[str, Any]:
    """
    Decode a qid://register?d=... URI back into a registration payload dict.
    """
    prefix = "qid://"
    if not uri.startswith(prefix):
        raise ValueError("Not a Q-ID URI (missing 'qid://' prefix).")

    rest = uri[len(prefix) :]
    if "?" not in rest:
        raise ValueError("Q-ID URI missing query part.")
    action, query = rest.split("?", 1)

    if action != "register":
        raise ValueError(f"Unsupported Q-ID action for registration: {action!r}")

    token = None
    for pair in query.split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        if key == "d":
            token = value
            break

    if token is None:
        raise ValueError("Q-ID registration URI missing 'd' parameter.")

    try:
        data_bytes = _b64url_decode(token)
        payload = json.loads(data_bytes.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Failed to decode Q-ID registration payload.") from exc

    if not isinstance(payload, dict):
        raise ValueError("Q-ID registration payload must be a JSON object.")

    return payload


# ---------------------------------------------------------------------------
# Placeholders for future full protocol flows
# ---------------------------------------------------------------------------


def register_identity(request: Dict[str, Any]) -> Dict[str, Any]:
    return {"status": "todo", "detail": "Q-ID registration not implemented yet."}


def login(request: Dict[str, Any]) -> Dict[str, Any]:
    return {"status": "todo", "detail": "Q-ID login not implemented yet."}
