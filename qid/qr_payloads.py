"""
QR payload handling for DigiByte Q-ID.

This module stays intentionally thin.

Contract source of truth:
- qid.uri_scheme (canonical qid:// encoding/decoding rules)

We keep these functions for compatibility with existing tests/callers:
- encode_login_request(payload) -> "qid://login?d=..."
- decode_login_request(uri) -> dict
"""

from __future__ import annotations

from typing import Any, Dict

from .uri_scheme import decode_login_request as _decode_login_request
from .uri_scheme import encode_login_request as _encode_login_request


def encode_login_request(payload: Dict[str, Any]) -> str:
    """
    Convert a login-request dictionary into a Q-ID URI.

    Expected output format (contract):
        qid://login?d=<base64url(JSON)>
    """
    # payload is validated at higher levels / by contract tests.
    return _encode_login_request(payload)


def decode_login_request(uri: str) -> Dict[str, Any]:
    """
    Parse a Q-ID login URI back into a dictionary.

    Raises ValueError if the URI is invalid or cannot be decoded.
    """
    return _decode_login_request(uri)
