# DigiByte Q-ID — Reference API Server (Skeleton v0.1)

Status: **skeleton – login + registration verification**

This document sketches a simple HTTP/JSON API that DigiByte-enabled
services can use to verify Q-ID registration and login responses.

The goal is to keep integration easy for backend developers, while
remaining compatible with future upgrades (PQC, Guardian, Shield, etc.).

---

## 1. General Principles

- All endpoints are served over **HTTPS**.
- All requests and responses use `application/json`.
- Services are free to adapt field names internally, but SHOULD keep the
  wire format consistent with this document to remain compatible with
  reference tooling.

This document does **not** yet define signature formats. For now,
`signature` fields are treated as opaque strings that the verifier
passes to a crypto backend.

---

## 2. Registration Flow (High Level)

1. Service generates a **registration request payload**:

   ```jsonc
   {
     "type": "registration",
     "service_id": "example.com",
     "address": "dgb1qxyz123example",
     "pubkey": "EXAMPLEPUBKEY",
     "nonce": "abcdef123456",
     "callback_url": "https://example.com/qid/register",
     "version": "1"
   }
   ```

2. Service encodes it into a Q-ID URI:

   ```text
   qid://register?d=<base64url(JSON)>
   ```

3. Wallet scans QR / opens deeplink, asks the user to confirm.

4. Wallet builds a **registration response** JSON and POSTs it to the
   service’s `callback_url`.

5. Service forwards the payload to its local or remote **Q-ID verifier**
   API (described below), which performs all checks.

---

## 3. Endpoint: Verify Registration

### 3.1 URL

```text
POST /qid/register/verify
```

### 3.2 Request Body (v0.1 draft)

```jsonc
{
  "request": {
    "type": "registration",
    "service_id": "example.com",
    "address": "dgb1qxyz123example",
    "pubkey": "EXAMPLEPUBKEY",
    "nonce": "abcdef123456",
    "callback_url": "https://example.com/qid/register",
    "version": "1"
  },
  "response": {
    "identity_id": "qid:example-user-123",
    "address": "dgb1qxyz123example",
    "pubkey": "EXAMPLEPUBKEY",
    "key_algorithm": "secp256k1",
    "signature": "BASE64_SIGNATURE",
    "signed_at": "2025-01-01T12:34:56Z"
  },
  "context": {
    "client_ip": "203.0.113.10",
    "user_agent": "ExampleWallet/1.0",
    "device_id": "device-abc",
    "request_received_at": "2025-01-01T12:34:56Z"
  }
}
```

- `request` – original registration payload that was encoded inside the
  Q-ID URI.
- `response` – data returned by the wallet. Exact fields may evolve
  as cryptography and device-binding details are specified.
- `context` – optional metadata that the service or API server may use
  for logging and risk analysis.

### 3.3 Response Body (v0.1 draft)

```jsonc
{
  "ok": true,
  "reason": "registration_accepted",
  "identity_id": "qid:example-user-123",
  "credential_id": "cred-xyz",
  "level": 1,
  "warnings": []
}
```

Possible values:

- `ok` – boolean, true if registration is accepted.
- `reason` – short machine-readable string (e.g. `registration_accepted`,
  `invalid_signature`, `nonce_mismatch`).
- `identity_id` – internal identifier for the Q-ID identity.
- `credential_id` – identifier for the created binding between identity
  and service.
- `level` – assurance level (1 = basic; higher = stronger verification).
- `warnings` – list of non-fatal strings providing extra context.

In case of hard failures, `ok` is `false` and `reason` explains why.

---

## 4. Login Flow (High Level)

1. Service generates a **login request payload**:

   ```jsonc
   {
     "type": "login_request",
     "service_id": "example.com",
     "nonce": "random-unique-string",
     "callback_url": "https://example.com/qid/callback",
     "version": "1"
   }
   ```

2. Service encodes it into:

   ```text
   qid://login?d=<base64url(JSON)>
   ```

3. Wallet scans QR / opens deeplink, locates the existing credential for
   this `service_id`, asks the user to approve.

4. Wallet builds a **login response** and POSTs it to `callback_url`.

5. Service forwards the payload to `/qid/login/verify`.

---

## 5. Endpoint: Verify Login

### 5.1 URL

```text
POST /qid/login/verify
```

### 5.2 Request Body (v0.1 draft)

```jsonc
{
  "request": {
    "type": "login_request",
    "service_id": "example.com",
    "nonce": "random-unique-string",
    "callback_url": "https://example.com/qid/callback",
    "version": "1"
  },
  "response": {
    "identity_id": "qid:example-user-123",
    "credential_id": "cred-xyz",
    "address": "dgb1qxyz123example",
    "key_id": "key-1",
    "signature": "BASE64_SIGNATURE",
    "signed_at": "2025-01-01T12:34:56Z"
  },
  "context": {
    "client_ip": "203.0.113.10",
    "user_agent": "ExampleWallet/1.0",
    "device_id": "device-abc",
    "request_received_at": "2025-01-01T12:34:56Z"
  }
}
```

### 5.3 Response Body (v0.1 draft)

```jsonc
{
  "ok": true,
  "reason": "login_accepted",
  "identity_id": "qid:example-user-123",
  "credential_id": "cred-xyz",
  "level": 1,
  "session": {
    "session_id": "sess-123",
    "expires_at": "2025-01-01T14:34:56Z"
  },
  "warnings": []
}
```

The verifier is responsible for:

- checking that `request.service_id` matches the expected service,
- validating `nonce` (not reused, not expired),
- validating signatures (once signature formats are specified),
- enforcing policy decisions (assurance level, device trust, etc.).

---

## 6. Error Handling

On protocol errors (invalid JSON, malformed fields), the API server
SHOULD return HTTP 400 with a body like:

```jsonc
{
  "ok": false,
  "reason": "invalid_request",
  "details": "Missing field: response.signature"
}
```

On internal errors (database down, unexpected exception), the API server
SHOULD return HTTP 500 with:

```jsonc
{
  "ok": false,
  "reason": "internal_error"
}
```

`details` MAY be omitted or reduced in production for security reasons.

---

## 7. Future Work

Future versions of this document will:

- Specify exact signature algorithms and proof formats.
- Define how PQC and hybrid keys are represented.
- Link responses more tightly to the `QIDIdentity`, `QIDKey`,
  `QIDCredential` models.
- Add examples of integrating Guardian/Shield risk scores into responses.
