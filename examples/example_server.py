"""
examples/example_server.py

Tiny demo HTTP server showing how a DigiByte Q-ID enabled service
could:

- expose a Q-ID login URI (for QR / deep-link),
- receive a signed login response from a wallet,
- verify the signature on the server side.

⚠️ This is a documentation / demo server ONLY.
Do NOT use this as-is in production.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict

from qid.crypto import QIDKeyPair, generate_dev_keypair
from qid.integration.adamantine import (
    QIDServiceConfig,
    build_qid_login_uri,
    verify_signed_login_response_server,
)

# ---------------------------------------------------------------------------
# Demo service configuration
# ---------------------------------------------------------------------------

SERVICE = QIDServiceConfig(
    service_id="example.com",
    callback_url="https://example.com/qid/callback",
    display_name="Example DigiByte Q-ID Service",
)

# For the demo we generate an in-memory dev keypair.
# In a real deployment the service would store its keys securely (HSM, KMS, etc.)
DEV_KEYPAIR: QIDKeyPair = generate_dev_keypair()

# We keep the last login URI in memory so that /verify can check against it.
LAST_LOGIN_URI: str | None = None


class QIDDemoHandler(BaseHTTPRequestHandler):
    """Very small HTTP handler for Q-ID demo flows."""

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------ #
    # GET /login  -> issue a Q-ID login URI for the user                 #
    # ------------------------------------------------------------------ #
    def do_GET(self) -> None:  # type: ignore[override]
        global LAST_LOGIN_URI

        if self.path.startswith("/login"):
            # In real life this should be a fresh, random nonce per request.
            nonce = "demo-nonce-123"

            login_uri = build_qid_login_uri(SERVICE, nonce=nonce)
            LAST_LOGIN_URI = login_uri

            self._send_json(
                200,
                {
                    "login_uri": login_uri,
                    "message": "Show this URI as a QR code or deep-link.",
                },
            )
        else:
            self._send_json(404, {"error": "not_found"})

    # ------------------------------------------------------------------ #
    # POST /verify  -> verify a signed login response from the wallet    #
    # Body: { "response_payload": {...}, "signature": "..." }            #
    # ------------------------------------------------------------------ #
    def do_POST(self) -> None:  # type: ignore[override]
        global LAST_LOGIN_URI

        if not self.path.startswith("/verify"):
            self._send_json(404, {"error": "not_found"})
            return

        if LAST_LOGIN_URI is None:
            self._send_json(
                400,
                {
                    "ok": False,
                    "error": "no_login_request_issued",
                    "detail": "Call /login first to get a Q-ID login URI.",
                },
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0

        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "invalid_json"})
            return

        response_payload = data.get("response_payload") or {}
        signature = data.get("signature") or ""

        ok = verify_signed_login_response_server(
            service=SERVICE,
            login_uri=LAST_LOGIN_URI,
            response_payload=response_payload,
            signature=signature,
            keypair=DEV_KEYPAIR,
        )

        self._send_json(200, {"ok": ok})


def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Start the demo HTTP server."""
    server = HTTPServer((host, port), QIDDemoHandler)
    print(f"Q-ID demo server listening on http://{host}:{port}")
    print("  • GET  /login   -> returns a qid:// login URI")
    print("  • POST /verify  -> verifies a signed login response")
    server.serve_forever()


if __name__ == "__main__":
    run()
