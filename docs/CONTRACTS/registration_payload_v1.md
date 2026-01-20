<!--
MIT License
Copyright (c) 2025 DarekDGB
-->

# Registration Payload v1 (Normative Contract)

This contract defines the **registration payload** format for DigiByte Q-ID,
including required fields and fail-closed validation rules.

If code or tests conflict with this contract, **this contract wins**.

---

## 1. Canonical Serialization

All payloads MUST be treated as JSON objects and MUST be serialized to bytes using
**canonical JSON** for signing and verification:

- UTF-8
- `sort_keys = true`
- separators = `(",", ":")`
- no whitespace

(See `crypto_envelope_v1.md` for how canonical bytes are used.)

---

## 2. Registration Payload

### 2.1 Type
`type` MUST equal:

- `"registration"`

### 2.2 Required Fields

A registration payload MUST include:

- `type` (string) = `"registration"`
- `service_id` (string) — relying party identifier (e.g. domain)
- `address` (string) — wallet address claimed by the user
- `pubkey` (string) — public key material (format defined by implementation)
- `nonce` (string) — unpredictable challenge for registration
- `callback_url` (string) — where the wallet/app returns the signed registration
- `version` (string) — protocol version label (default `"1"`)

### 2.3 Validation Rules (Fail-Closed)

A verifier MUST reject the payload if:

- any required field is missing
- any required field is not a string
- `type != "registration"`
- any required string is empty after trimming

No silent coercion is permitted.

---

## 3. Signing & Verification

Registration flows MAY be either:

- **Unsigned**: the payload is used only as a URI-embedded request
- **Signed**: the payload is signed using **Crypto Envelope v1**

If signed:
- the exact JSON object MUST be signed (canonical JSON bytes)
- verification MUST be fail-closed
- no downgrade or silent fallback

---

## 4. Security Notes (Non-Normative)

- Nonce MUST be unique per registration attempt.
- Registration SHOULD be idempotent at the relying party layer using (service_id, address)
  to prevent duplicates.
- Callback URL allowlists are recommended at the relying party layer.

---

**Author:** DarekDGB  
**License:** MIT (2025)
