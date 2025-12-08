"""
High-level DigiByte Q-ID protocol helpers.

Right now this module focuses on the *login* flow only, with simple
helpers that work together with `qr_payloads`:

- build_login_request_payload(...)
- build_login_request_uri(...)
- parse_login_request_uri(...)

Real registration / revocation / recovery logic will be added later.
"""

from __future__ import annotations

from typing import Any, Dict

from .qr_payloads import encode_login_request, decode_login_request


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
# Placeholders for future full protocol flows
# ---------------------------------------------------------------------------


def register_identity(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Placeholder registration flow.

    In the future this will:
    - bind a Q-ID identity to a service
    - create QIDCredential objects
    - coordinate with crypto + storage layers
    """
    return {"status": "todo", "detail": "Q-ID registration not implemented yet."}


def login(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Placeholder login flow.

    In the future this will:
    - verify signatures from the wallet
    - look up the corresponding QIDCredential
    - apply policy / trust checks
    """
    return {"status": "todo", "detail": "Q-ID login not implemented yet."}
