# DigiByte Q-ID — Server Integration Guide

Status: **draft – reference flow for integrators**

This guide explains how a backend / service ("relying party") can add
**Login with DigiByte Q-ID** support using the reference Python helpers
provided in this repo.

It focuses on **server-side logic** and assumes that:

- A wallet such as **DigiByte Adamantine** handles the user side.
- The service can run Python (for the reference implementation). Other
  stacks can mirror the same logic.

Key modules:

- `qid.protocol`
- `qid.crypto`
- `qid.integration.adamantine`

---

## 1. High-level flow

1. The service generates a **Q-ID login request URI**:

   ```python
   from qid.integration.adamantine import QIDServiceConfig, build_qid_login_uri

   service = QIDServiceConfig(
       service_id="example.com",
       callback_url="https://example.com/qid/callback",
   )

   nonce = "random-unique-nonce"  # generate securely
   login_uri = build_qid_login_uri(service, nonce)
   ```

2. The service presents `login_uri` as a **QR code** or deep-link.

3. The wallet (Adamantine) scans the QR / receives the link, builds a
   **signed login response**, and POSTs it to `callback_url`.

4. The service verifies the response using
   `verify_signed_login_response_server(...)` and creates a session.

The rest of this document details these steps.

---

## 2. Generating the login request

### 2.1. Service configuration

The service needs a stable `service_id` and `callback_url`:

```python
from qid.integration.adamantine import QIDServiceConfig

service = QIDServiceConfig(
    service_id="example.com",
    callback_url="https://example.com/qid/callback",
)
```

- `service_id` is included in the Q-ID payload so wallets can ensure they
  are signing for the **intended** relying party.
- `callback_url` tells the wallet where to send the login response.

### 2.2. Building the URI

```python
from qid.integration.adamantine import build_qid_login_uri

nonce = "random-unique-nonce"  # use a secure random generator in production
login_uri = build_qid_login_uri(service, nonce)
```

The returned string looks like:

```text
qid://login?d=<base64url(JSON)>
```

The service should:

- Render this as a QR code on a web page, **or**
- Use it as a mobile deep-link (`qid://...`) if the wallet runs on the
  same device.

---

## 3. Wallet → server: expected callback payload

The reference wallet flow (Adamantine) uses:

```python
from qid.integration.adamantine import prepare_signed_login_response
```

It produces:

- `response_payload` – the Q-ID login response JSON.
- `signature` – cryptographic signature over `response_payload`.

A simple HTTP POST body to `callback_url` might look like:

```json
{
  "qid_version": "1",
  "login_request_uri": "qid://login?d=...",
  "response_payload": {
    "type": "login_response",
    "service_id": "example.com",
    "nonce": "random-unique-nonce",
    "callback_url": "https://example.com/qid/callback",
    "address": "dgb1qxyz123example",
    "pubkey": "wallet-public-key",
    "key_id": "primary",
    "version": "1"
  },
  "signature": "base64url-signature"
}
```

The exact JSON shape and HTTP details are **not** fixed by Q-ID; this is
a suggested pattern. What *is* important is:

- The `login_request_uri` matches the original request.
- The `response_payload` is the JSON that was signed.
- The `signature` was produced by the wallet over that payload.

---

## 4. Verifying a login response

On the server, once the POST is received:

```python
from qid.crypto import QIDKeyPair
from qid.integration.adamantine import (
    QIDServiceConfig,
    verify_signed_login_response_server,
)

# 1. Your configured service
service = QIDServiceConfig(
    service_id="example.com",
    callback_url="https://example.com/qid/callback",
)

# 2. Your configured Q-ID keypair (dev backend shown here)
# In production, this would be a PQC / hybrid key loaded from secure storage.
keypair = QIDKeyPair(
    id="dev-hmac-primary",
    public_key="dev-hmac-primary",
    secret_key=b"...",  # load from config / vault
)

# 3. Extract fields from HTTP request
login_request_uri = body["login_request_uri"]
response_payload = body["response_payload"]
signature = body["signature"]

ok = verify_signed_login_response_server(
    service=service,
    login_uri=login_request_uri,
    response_payload=response_payload,
    signature=signature,
    keypair=keypair,
)

if not ok:
    # reject login
    ...
else:
    # accept login, create or resume a session
    address = response_payload["address"]
    # bind this address / identity to a user account
    ...
```

What `verify_signed_login_response_server()` checks:

1. The `login_uri` parses correctly.
2. `service_id` and `callback_url` inside the URI match your expected
   `QIDServiceConfig`.
3. The `response_payload` and `signature` pass the cryptographic checks
   in `server_verify_login_response(...)`.

---

## 5. Session handling & account binding

Once a Q-ID login is verified:

- The service can create a **session** for the user.
- The session may be associated with:
  - the DigiByte `address`
  - the Q-ID `key_id`
  - any internal user ID.

Typical patterns:

- First login:
  - Create a new account bound to `(service_id, address, key_id)`.
- Subsequent logins:
  - Look up the account by `(service_id, address, key_id)` and resume
    the session.

---

## 6. Security notes & best practices

- **Nonce handling**:
  - Nonces should be unique and short-lived.
  - Store outstanding nonces server-side and mark them as used once a
    login succeeds.
- **Replay protection**:
  - Reject responses that reuse a nonce.
  - Consider adding timestamps or expiry fields in future versions.
- **Rate limiting**:
  - Apply rate limits per IP / device / identity to prevent abuse.
- **Transport security**:
  - Always use HTTPS for `callback_url`.
- **Key management**:
  - For now, the dev backend uses an HMAC secret key; in production,
    migrate to a PQC / hybrid backend and store keys in a secure vault.

---

## 7. Future: PQC backends & Guardian / Shield

As Q-ID evolves:

- `qid.crypto` will support **post-quantum** backends (ML-DSA, Falcon,
  hybrids).
- The server-side verification code can stay the same; only key loading
  and the underlying backend change.
- Integration with **Guardian / Shield** can:
  - log Q-ID login events,
  - score risk,
  - detect anomalies across many services.

This guide, combined with the Python helpers in
`qid.integration.adamantine`, gives services a clear starting point to
offer **Login with DigiByte Q-ID** while staying ready for a
post-quantum future.
