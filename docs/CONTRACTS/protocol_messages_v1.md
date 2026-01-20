# Q-ID Protocol Message Shapes v1

Author: DarekDGB  
License: MIT (2025)

## Status
Contract-locked (v1)

## Purpose
Defines canonical JSON payload shapes used by DigiByte Q-ID.

All payloads:
- MUST be JSON objects
- MUST be canonicalized before signing
- MUST include `type` and `version`

---

## Login Request Payload

```json
{
  "type": "login_request",
  "service_id": "string",
  "nonce": "string",
  "callback_url": "string",
  "version": "1"
}
```

Required fields:
- type
- service_id
- nonce
- callback_url
- version

---

## Login Response Payload

```json
{
  "type": "login_response",
  "service_id": "string",
  "nonce": "string",
  "address": "string",
  "pubkey": "string",
  "version": "1",
  "key_id": "string (optional)"
}
```

---

## Registration Payload

```json
{
  "type": "registration",
  "service_id": "string",
  "address": "string",
  "pubkey": "string",
  "nonce": "string",
  "callback_url": "string",
  "version": "1"
}
```

## Rejection Rules
- Missing required field → reject
- Unknown `type` → reject
- Version mismatch → reject

## Security Notes
- No implicit defaults
- No silent field dropping
- No auto-upgrade of versions

