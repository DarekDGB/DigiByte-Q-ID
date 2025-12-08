"""
QR payload handling for DigiByte Q-ID.

We use a simple format:

    qid://login?d=<base64url(JSON)>

Where the decoded JSON for a login request should look like:

{
  "type": "login_request",
  "service_id": "example.com",
  "nonce": "random-unique-string",
  "callback_url": "https://example.com/qid/callback",
  "version": "1"
}

Later we can extend this with more fields (algorithms, PQC options, etc.).
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(token: str) -> bytes:
    """Decode URL-safe base64 without padding."""
    padding = "=" * (-len(token) % 4)
    return base64.urlsafe_b64decode(token + padding)


def encode_login_request(payload: Dict[str, Any]) -> str:
    """
    Convert a login-request dictionary into a Q-ID URI.

    The caller is responsible for providing a well-formed payload.
    We just JSON-encode it and wrap it into:

        qid://login?d=<base64url(JSON)>
    """
    json_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    token = _b64url_encode(json_str.encode("utf-8"))
    return f"qid://login?d={token}"


def decode_login_request(uri: str) -> Dict[str, Any]:
    """
    Parse a Q-ID login URI back into a dictionary.

    Expected format: qid://login?d=<base64url(JSON)>

    Raises ValueError if the URI is invalid or cannot be decoded.
    """
    prefix = "qid://"
    if not uri.startswith(prefix):
        raise ValueError("Not a Q-ID URI (missing 'qid://' prefix).")

    # Strip scheme and split the rest into action + query string.
    rest = uri[len(prefix) :]  # e.g. "login?d=abc"
    if "?" not in rest:
        raise ValueError("Q-ID URI missing query part.")
    action, query = rest.split("?", 1)

    if action != "login":
        raise ValueError(f"Unsupported Q-ID action: {action!r}")

    # Very small query parser: look for d=<token>
    token = None
    for pair in query.split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        if key == "d":
            token = value
            break

    if token is None:
        raise ValueError("Q-ID URI missing 'd' parameter.")

    try:
        data_bytes = _b64url_decode(token)
        payload = json.loads(data_bytes.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Failed to decode Q-ID login payload.") from exc

    if not isinstance(payload, dict):
        raise ValueError("Q-ID payload must be a JSON object.")

    return payload
