from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from qid.crypto import QIDKeyPair, sign_payload, verify_payload


@dataclass(frozen=True)
class SignedMessage:
    """
    Signed protocol message.

    Fields are intentionally minimal and deterministic:
    - payload: canonical-json-signable dict (caller responsibility to keep it JSON-safe)
    - signature: crypto envelope v1 (base64(canonical_json))
    - algorithm: protocol-visible algorithm ID (mirrors keypair.algorithm)
    - hybrid_container_b64: optional; required only for HYBRID real-backend verification/signing
    """
    payload: Dict[str, Any]
    signature: str
    algorithm: str
    hybrid_container_b64: Optional[str] = None


def sign_message(
    payload: Dict[str, Any],
    keypair: QIDKeyPair,
    *,
    hybrid_container_b64: Optional[str] = None,
) -> SignedMessage:
    """
    Sign a payload and return a SignedMessage wrapper.

    Fail-closed rule:
    - If the crypto layer requires hybrid_container_b64 (real backend + HYBRID),
      it must be provided by the caller.
    """
    sig = sign_payload(payload, keypair, hybrid_container_b64=hybrid_container_b64)
    return SignedMessage(
        payload=payload,
        signature=sig,
        algorithm=keypair.algorithm,
        hybrid_container_b64=hybrid_container_b64,
    )


def verify_message(msg: SignedMessage, keypair: QIDKeyPair) -> bool:
    """
    Verify a SignedMessage using the provided keypair.

    Fail-closed rule:
    - If a hybrid container is required, verification will be False unless present.
    """
    return verify_payload(
        msg.payload,
        msg.signature,
        keypair,
        hybrid_container_b64=msg.hybrid_container_b64,
    )
