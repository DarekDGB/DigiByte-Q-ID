"""
QR payload handling for DigiByte Q-ID.

This module is intentionally thin.

All URI encoding/decoding rules live in:
    qid/uri_scheme.py

We keep these wrappers to preserve the earlier public API used by tests and
integrations.

Login URI format:
    qid://login?d=<base64url(JSON)>
"""

from __future__ import annotations

from typing import Any, Dict

from .uri_scheme import (
    encode_login_request,
    decode_login_request,
)


def build_qr_payload(payload: Dict[str, Any]) -> str:
    """
    Back-compat generic builder used by older tests.
    For now this is equivalent to encoding a login request.
    """
    return encode_login_request(payload)


def parse_qr_payload(uri: str) -> Dict[str, Any]:
    """
    Back-compat generic parser used by older tests.
    For now this is equivalent to decoding a login request URI.
    """
    return decode_login_request(uri)


def encode_login_request_uri(payload: Dict[str, Any]) -> str:
    """Backwards compatible wrapper (older code used *_uri suffix)."""
    return encode_login_request(payload)


def decode_login_request_uri(uri: str) -> Dict[str, Any]:
    """Backwards compatible wrapper (older code used *_uri suffix)."""
    return decode_login_request(uri)
