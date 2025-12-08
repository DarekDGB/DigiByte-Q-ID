"""
QR payload handling for DigiByte Q-ID.

This module will later:
- Build Q-ID login QR payloads
- Build Q-ID registration QR payloads
- Parse Q-ID URIs (qid://...)
- Validate required fields

Currently only placeholder functions exist.
"""

from typing import Dict, Any


def encode_login_request(payload: Dict[str, Any]) -> str:
    """Placeholder: convert a login payload into a Q-ID URI."""
    return "qid://TODO-login-request"


def decode_login_request(uri: str) -> Dict[str, Any]:
    """Placeholder: decode a Q-ID URI back into a login request dict."""
    return {"todo": "decode login request from URI"}
