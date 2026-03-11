from __future__ import annotations

import pytest

import qid.binding as binding
import qid.crypto as crypto
import qid.pqc.pqc_falcon as pf
import qid.pqc.pqc_ml_dsa as pmd
import qid.pqc.keygen_liboqs as kl
import qid.pqc_backends as pb
import qid.pqc_sign as ps
import qid.pqc_verify as pv
from qid.crypto import QIDKeyPair, generate_dev_keypair
from qid.hybrid_key_container import build_container, encode_container
from qid.integration.adamantine import build_adamantine_qid_evidence_v2


class _FallbackSignerReturnsBytes:
    def __init__(self) -> None:
        self.after_import = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    @property
    def secret_key(self) -> bytes:
        return b""

    @secret_key.setter
    def secret_key(self, value: bytes) -> None:
        self.after_import = True

    def sign(self, msg: bytes, priv: bytes | None = None) -> bytes:
        if priv is not None:
            raise TypeError("need imported secret")
        if not self.after_import:
            raise TypeError("not imported yet")
        return b"ok:" + msg


class _FallbackSignerReturnsNone(_FallbackSignerReturnsBytes):
    def sign(self, msg: bytes, priv: bytes | None = None):
        if priv is not None:
            raise TypeError("need imported secret")
        if not self.after_import:
            raise TypeError("not imported yet")
        return None


class _NoKwFactory:
    def __init__(self, signer_cls):
        self.signer_cls = signer_cls

    def __call__(self, alg: str, secret_key: bytes | None = None):
        if secret_key is not None:
            raise TypeError("ctor kwargs unsupported")
        return self.signer_cls()


class _OQSBytes:
    Signature = _NoKwFactory(_FallbackSignerReturnsBytes)


class _OQSNone:
    Signature = _NoKwFactory(_FallbackSignerReturnsNone)


class _SecretExportMethodBadAttr:
    def export_secret_key(self):
        return "nope"

    secret_key = "still-nope"
    _sk = b"good"


class _VerifyModule:
    class Signature:
        def __init__(self, alg: str):
            self.alg = alg

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def verify(self, msg: bytes, sig: bytes, pub: bytes) -> bool:
            if self.alg == "ML-DSA-44":
                raise RuntimeError("first candidate fails")
            return True


def test_adamantine_v2_without_hybrid_container_covers_false_branch() -> None:
    evidence = build_adamantine_qid_evidence_v2(
        login_uri="qid://login?d=x",
        response_payload={"address": "dgb1", "issued_at": 1, "expires_at": 2},
        signature="sig",
    )
    assert "hybrid_container_b64" not in evidence


@pytest.mark.parametrize(
    ("payload", "now"),
    [
        ({"created_at": "bad", "expires_at": 10}, 5),
        ({"created_at": 1, "expires_at": "bad"}, 5),
    ],
)
def test_verify_binding_time_type_guards_with_validation_bypassed(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    now: int,
) -> None:
    base = {
        "version": "1",
        "type": "binding",
        "domain": "svc",
        "address": "D",
        "policy": "ml-dsa",
        "pqc_pubkeys": {"ml_dsa": "AA", "falcon": None},
        **payload,
    }
    monkeypatch.setattr(binding, "validate_binding_payload", lambda p: None)
    env = {"binding_id": binding.compute_binding_id(base), "payload": base, "sig": "sig"}
    assert verify_binding_result(env, now) is False


def verify_binding_result(env: dict[str, object], now: int) -> bool:
    return binding.verify_binding(
        env,
        generate_dev_keypair(),
        expected_domain="svc",
        now=now,
    )


def test_falcon_fallback_sign_paths_cover_remaining_lines() -> None:
    assert pf.sign_falcon(oqs=_OQSBytes(), msg=b"m", priv=b"k") == b"ok:m"
    with pytest.raises(RuntimeError, match="pqc_falcon signing failed"):
        pf.sign_falcon(oqs=_OQSNone(), msg=b"m", priv=b"k")


def test_ml_dsa_fallback_sign_paths_cover_remaining_lines() -> None:
    assert pmd.sign_ml_dsa(oqs=_OQSBytes(), msg=b"m", priv=b"k") == b"ok:m"
    with pytest.raises(RuntimeError, match="pqc_ml_dsa signing failed"):
        pmd.sign_ml_dsa(oqs=_OQSNone(), msg=b"m", priv=b"k")


def test_export_secret_key_falls_back_to_private_attr() -> None:
    assert kl._export_secret_key(_SecretExportMethodBadAttr()) == b"good"


def test_pqc_backends_remaining_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    assert pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO) is None

    monkeypatch.setattr(pb, "_oqs_alg_candidates_for", lambda alg: ("X",))
    monkeypatch.setattr(pb, "_import_oqs", lambda: _VerifyModule)

    with pytest.raises(pb.PQCBackendError, match="liboqs signing failed"):
        pb.liboqs_sign("unexpected", b"m", b"k")

    with pytest.raises(ValueError, match="Unsupported algorithm for liboqs"):
        pb.liboqs_verify("unexpected", b"m", b"s", b"p")


def test_pqc_sign_missing_secret_key_for_falcon_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"type": "login_response", "service_id": "svc", "nonce": "n"}
    monkeypatch.setattr(ps, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(ps, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    with pytest.raises(ValueError, match="missing secret_key"):
        ps.sign_pqc_login_fields(
            payload,
            pqc_alg=pb.FALCON_ALGO,
            falcon_keypair=QIDKeyPair(
                algorithm=pb.FALCON_ALGO,
                public_key="AA==",
                secret_key="",
            ),
        )


def test_pqc_verify_remaining_false_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="invalid base64url"):
        pv._b64url_decode("a!")

    assert pv.verify_pqc_login(login_payload={}, binding_env=[]) is False

    monkeypatch.setattr(pv, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pv, "_policy_allows_alg", lambda alg, policy: True)

    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": "weird"},
        binding_env={"payload": {"policy": "ml-dsa", "pqc_pubkeys": {}}},
    ) is False


def test_crypto_remaining_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(crypto, "_ALLOWED_ALGOS", set(crypto._ALLOWED_ALGOS) | {"weird"}, raising=False)

    with pytest.raises(ValueError, match="Unsupported algorithm for signing"):
        crypto.sign_payload(
            {"x": 1},
            QIDKeyPair(
                algorithm="weird",
                public_key="AA==",
                secret_key="AA==",
            ),
        )

    monkeypatch.setattr(crypto, "selected_backend", lambda: "liboqs", raising=False)
    monkeypatch.setattr(crypto, "enforce_no_silent_fallback_for_alg", lambda alg: None, raising=False)
    monkeypatch.setattr(crypto, "liboqs_verify", lambda *a, **k: True, raising=False)

    assert crypto.verify_payload(
        {"x": 1},
        crypto._envelope_encode({"v": crypto._SIG_ENVELOPE_VERSION, "alg": pb.ML_DSA_ALGO}),
        QIDKeyPair(
            algorithm=pb.ML_DSA_ALGO,
            public_key="AA==",
            secret_key="AA==",
        ),
    ) is False

    assert crypto.verify_payload(
        {"x": 1},
        crypto._envelope_encode(
            {
                "v": crypto._SIG_ENVELOPE_VERSION,
                "alg": pb.HYBRID_ALGO,
                "sigs": {pb.ML_DSA_ALGO: "AA"},
            }
        ),
        QIDKeyPair(
            algorithm=pb.HYBRID_ALGO,
            public_key="AA==",
            secret_key="AA==",
        ),
        hybrid_container_b64=encode_container(
            build_container(
                kid="kid",
                ml_dsa_public_key="AA==",
                falcon_public_key="AA==",
            )
        ),
    ) is False

    monkeypatch.setattr(
        crypto,
        "liboqs_verify",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        raising=False,
    )

    assert crypto.verify_payload(
        {"x": 1},
        crypto._envelope_encode(
            {
                "v": crypto._SIG_ENVELOPE_VERSION,
                "alg": pb.HYBRID_ALGO,
                "sigs": {pb.ML_DSA_ALGO: "AA", pb.FALCON_ALGO: "AA"},
            }
        ),
        QIDKeyPair(
            algorithm=pb.HYBRID_ALGO,
            public_key="AA==",
            secret_key="AA==",
        ),
        hybrid_container_b64=encode_container(
            build_container(
                kid="kid",
                ml_dsa_public_key="AA==",
                falcon_public_key="AA==",
            )
        ),
    ) is False
