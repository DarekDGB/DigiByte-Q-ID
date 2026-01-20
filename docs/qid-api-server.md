<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# DigiByte Q-ID — API Server Notes (Non-Normative)

> **Status:** Developer guidance  
> **Normative rules live in `docs/CONTRACTS/`.**  
> If this document conflicts with a contract, **the contract wins**.

This document provides **implementation notes** for services that expose
Q-ID login and registration endpoints. It is **not** a protocol specification.

---

## 1. Purpose of an API server

A Q-ID API server typically:
- issues **login requests**
- verifies **signed login responses**
- accepts **registration payloads**
- enforces service-specific policy (outside Q-ID scope)

Q-ID itself does **not** define:
- user databases
- session handling
- authorization logic
- account recovery

Those concerns remain application-specific.

---

## 2. Login flow (server perspective)

### Step 1: Issue login request

The server:
1. Generates a nonce
2. Builds a login request payload
3. Encodes it as a `qid://login` URI
4. Presents it to the client (QR, deep link, etc.)

Helpers:
- `build_login_request_payload`
- `encode_login_request_uri`

---

### Step 2: Receive login response

The client returns:
- a signed login response payload
- a signature (Crypto Envelope v1)
- optional hybrid container (HYBRID only)

The server must:
- parse the response
- verify signature
- verify service_id and nonce match the original request

Helpers:
- `server_verify_login_response`

Any mismatch ⇒ **reject**.

---

## 3. Registration flow (server perspective)

Registration is a **one-time association** between:
- a DigiByte address
- a public key
- a service identifier

The server:
1. issues a registration request (out of band or via QR)
2. receives a signed registration payload
3. verifies signature
4. stores association according to its own rules

Q-ID does **not** define:
- how keys are rotated
- how identities are revoked
- how duplicates are resolved

---

## 4. Cryptography expectations

Servers must be aware of backend mode:

### Stub mode (default)
- Deterministic signatures
- Suitable for development and CI
- **Not PQ-secure**

### Real backend (`liboqs`)
- Enforced PQC algorithms
- No silent fallback
- Hybrid requires explicit container

Servers may choose to:
- require `liboqs` mode
- accept stub mode for development only

---

## 5. Error handling (important)

Server implementations should:
- treat any verification failure as authentication failure
- never attempt partial acceptance
- log failures for audit (without leaking sensitive data)

Fail-closed behavior is mandatory.

---

## 6. Security boundaries

Q-ID guarantees:
- message authenticity (if verification succeeds)
- payload integrity
- explicit algorithm binding

Q-ID does **not** guarantee:
- user intent
- device security
- malware resistance
- account ownership semantics

Those are outside protocol scope.

---

## 7. Example server

See:
- `examples/example_server.py`

This example:
- uses DEV backend
- demonstrates verification logic
- is **not production-ready**

---

## License

MIT — Copyright (c) 2025 **DarekDGB**
