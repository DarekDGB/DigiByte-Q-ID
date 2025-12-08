# DigiByte Q-ID — Example Demo Web Server

**Status:** documentation / optional example  
**File:** `examples/example_server.py`

This document explains how the demonstration HTTP server works and how developers can use it to understand the **server-side role** in the DigiByte Q-ID authentication flow.

---

# 1. Purpose of the Demo Server

The goal of the example server is to show a minimal, self-contained implementation of:

### ✔ Generating a Q-ID login request  
- The server produces a `qid://` URI using:
  - service configuration  
  - a nonce  
  - callback information  
- This URI can be displayed as a QR code or opened via deep-link.

### ✔ Receiving a **signed login response** from the wallet  
- The wallet signs the login response payload using its identity key.  
- The server verifies the signature using the `qid.crypto` backend.

### ✔ Demonstrating a complete round-trip  
You can use this file together with `examples/login_roundtrip.py` to simulate both sides of the Q-ID ecosystem.

---

# 2. Endpoints Implemented

The server exposes two minimal endpoints:

---

### **GET `/login`**
Creates a fresh Q-ID login URI.

**Returns JSON:**

```json
{
  "login_uri": "qid://login?...",
  "message": "Show this URI as a QR code or deep-link."
}
```

The server also stores the URI in memory so `/verify` can validate it later.

---

### **POST `/verify`**

Accepts:

```json
{
  "response_payload": { ... },
  "signature": "..."
}
```

Then calls:

```python
verify_signed_login_response_server(...)
```

**Response:**

```json
{ "ok": true }
```

or:

```json
{ "ok": false }
```

This shows how a real service backend would verify Q-ID signatures.

---

# 3. Dev Keypair & Security Notes

The demo uses:

```python
generate_dev_keypair()
```

This is NOT for production.  
Real deployments must store their service private keys securely:

- Hardware Security Module (HSM)  
- Cloud KMS  
- Encrypted key storage with rotation  

The demo is intentionally simple so developers can inspect the Q-ID flow clearly.

---

# 4. Running the Server

From your repo root:

```bash
python examples/example_server.py
```

Output:

```
Q-ID demo server listening on http://127.0.0.1:8080
  • GET  /login
  • POST /verify
```

Test it with:

```
curl http://127.0.0.1:8080/login
```

Then POST a signed login response to:

```
http://127.0.0.1:8080/verify
```

---

# 5. How This Fits the Full Q-ID Architecture

This demo server connects directly to:

- `qid.integration.adamantine`  
- `qid.crypto`  
- `qid.protocol`  

It represents the **service-side** of the authentication flow:

```
Wallet  →  Scan QR  →  Build signed response  →  POST to service
Service →  Verify signature  →  Approve login
```

This makes the entire Q-ID concept easy for outside developers to understand.

---

# 6. What This Example Is *Not*

- NOT a full production server  
- NOT a secure backend implementation  
- NOT a real routing or wallet backend  
- NOT connected to DigiByte nodes  

It is purely a **teaching/inspection tool** and a **proof of concept**.

---

# 7. Next Steps (Optional Enhancements)

You may extend the example server with:

- Real database storage of service identities  
- Multi-device binding  
- Session issuance or JWT token creation  
- QR code PNG generation  
- HTTPS support  

These are optional and outside of the MVP scope.

---

## ✔ Completed  
Example server is now fully documented and ready to publish in your GitHub repo.
