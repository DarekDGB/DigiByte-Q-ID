from __future__ import annotations

import time

from qid.binding import (
    build_binding_payload,
    compute_binding_id,
    normalize_domain,
    validate_binding_payload,
)
from qid.pqc.pqc_ml_dsa import sign_ml_dsa, verify_ml_dsa
from qid.pqc.pqc_falcon import sign_falcon, verify_falcon
from qid.pqc.hybrid_dev_ml_dsa import sign_hybrid_strict_and, verify_hybrid_strict_and


# ---------------------------------------------------------------------------
# Binding coverage (pure logic, no signing)
# ---------------------------------------------------------------------------

def test_normalize_domain_variants() -> None:
    assert normalize_domain("Example.COM") == "example.com"
    assert normalize_domain(" example.com ") == "example.com"

    try:
        normalize_domain("https://example.com")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_binding_payload_validation_paths() -> None:
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="ml-dsa",
        ml_dsa_pub_b64u="ml",
        falcon_pub_b64u=None,
        created_at=100,
        expires_at=None,
    )
    validate_binding_payload(payload)

    bad = dict(payload)
    bad["policy"] = "unknown"
    try:
        validate_binding_payload(bad)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_binding_id_is_deterministic() -> None:
    payload = build_binding_payload(
        domain="example.com",
        address="ADDR",
        policy="falcon",
        ml_dsa_pub_b64u=None,
        falcon_pub_b64u="fa",
        created_at=100,
        expires_at=None,
    )
    assert compute_binding_id(payload) == compute_binding_id(payload)


# ---------------------------------------------------------------------------
# PQC helper coverage (NO oqs dependency)
# ---------------------------------------------------------------------------

class DummySignature:
    def __init__(self, alg: str):
        self.alg = alg

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def sign(self, msg: bytes, priv: bytes) -> bytes:
        return b"signed:" + msg + b":" + priv

    def verify(self, msg: bytes, sig: bytes, pub: bytes) -> bool:
        return sig == b"signed:" + msg + b":" + pub


class DummyOQS:
    Signature = DummySignature


def test_pqc_ml_dsa_helpers() -> None:
    oqs = DummyOQS()
    msg = b"m"
    priv = b"k"
    pub = b"k"

    sig = sign_ml_dsa(oqs=oqs, msg=msg, priv=priv)
    assert verify_ml_dsa(oqs=oqs, msg=msg, sig=sig, pub=pub) is True


def test_pqc_falcon_helpers() -> None:
    oqs = DummyOQS()
    msg = b"m"
    priv = b"k"
    pub = b"k"

    sig = sign_falcon(oqs=oqs, msg=msg, priv=priv)
    assert verify_falcon(oqs=oqs, msg=msg, sig=sig, pub=pub) is True


def test_hybrid_helpers_strict_and() -> None:
    oqs = DummyOQS()
    msg = b"m"

    sig_ml, sig_fa = sign_hybrid_strict_and(
        oqs=oqs,
        msg=msg,
        ml_dsa_priv=b"k",
        falcon_priv=b"k",
        ml_dsa_alg="Dilithium2",
        falcon_alg="Falcon-512",
    )

    assert verify_hybrid_strict_and(
        oqs=oqs,
        msg=msg,
        sig_ml=sig_ml,
        sig_fa=sig_fa,
        ml_dsa_pub=b"k",
        falcon_pub=b"k",
        ml_dsa_alg="Dilithium2",
        falcon_alg="Falcon-512",
    ) is True
