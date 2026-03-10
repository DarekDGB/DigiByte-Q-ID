from __future__ import annotations

import base64
import types

import pytest

import qid.binding as binding
import qid.crypto as crypto
import qid.pqc.pqc_falcon as pf
import qid.pqc.pqc_ml_dsa as pmd
import qid.pqc_backends as pb
import qid.pqc_sign as ps
import qid.pqc_verify as pv
from qid.crypto import QIDKeyPair, generate_dev_keypair
from qid.hybrid_key_container import build_container, encode_container
from qid.integration.adamantine import (
    QIDServiceConfig,
    build_adamantine_qid_evidence_v2,
    build_qid_login_uri,
    prepare_signed_login_response,
    verify_adamantine_qid_evidence,
)
from qid.integration.guardian import GuardianServiceConfig, build_guardian_qid_login_event
from qid.uri_scheme import decode_uri, encode_uri


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _service() -> QIDServiceConfig:
    return QIDServiceConfig(service_id="example.com", callback_url="https://example.com/qid")


def test_adamantine_v2_explicit_type_guards_and_kind_mismatch() -> None:
    with pytest.raises(TypeError, match="login_uri must be a non-empty string"):
        build_adamantine_qid_evidence_v2(
            login_uri="",
            response_payload={"address": "dgb1", "issued_at": 1, "expires_at": 2},
            signature="sig",
        )

    with pytest.raises(TypeError, match="response_payload must be a dict"):
        build_adamantine_qid_evidence_v2(
            login_uri="qid://login?d=x",
            response_payload="bad",  # type: ignore[arg-type]
            signature="sig",
        )

    with pytest.raises(TypeError, match="signature must be a non-empty string"):
        build_adamantine_qid_evidence_v2(
            login_uri="qid://login?d=x",
            response_payload={"address": "dgb1", "issued_at": 1, "expires_at": 2},
            signature="",
        )

    with pytest.raises(TypeError, match="hybrid_container_b64 must be a non-empty string if provided"):
        build_adamantine_qid_evidence_v2(
            login_uri="qid://login?d=x",
            response_payload={"address": "dgb1", "issued_at": 1, "expires_at": 2},
            signature="sig",
            hybrid_container_b64="",
        )

    kp = generate_dev_keypair()
    service = _service()
    login_uri = build_qid_login_uri(service, "n-kind")
    response_payload, signature = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address="dgb1kind",
        keypair=kp,
        now=10,
        ttl_seconds=10,
    )
    evidence = build_adamantine_qid_evidence_v2(
        login_uri=login_uri,
        response_payload=response_payload,
        signature=signature,
        hybrid_container_b64="AAEC",
    )
    bad = dict(evidence)
    bad["kind"] = "qid_login_v1"
    assert verify_adamantine_qid_evidence(service=service, evidence=bad, keypair=kp) is False


def test_guardian_missing_field_branches() -> None:
    service = _service()
    gservice = GuardianServiceConfig(service_id=service.service_id, callback_url=service.callback_url)
    login_uri = build_qid_login_uri(service, "n-guardian")
    kp = generate_dev_keypair()
    response_payload, signature = prepare_signed_login_response(
        service=service,
        login_uri=login_uri,
        address="dgb1guardian",
        keypair=kp,
    )

    bad_service = dict(response_payload)
    bad_service["service_id"] = ""
    with pytest.raises(TypeError, match="response_payload.service_id must be a non-empty string"):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad_service,
            qid_signature=signature,
        )

    bad_pub = dict(response_payload)
    bad_pub["pubkey"] = ""
    with pytest.raises(TypeError, match="response_payload.pubkey must be a non-empty string"):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad_pub,
            qid_signature=signature,
        )

    bad_mismatch = dict(response_payload)
    bad_mismatch["service_id"] = "other.example"
    with pytest.raises(TypeError, match="response_payload.service_id mismatch vs expected service"):
        build_guardian_qid_login_event(
            service=gservice,
            login_uri=login_uri,
            response_payload=bad_mismatch,
            qid_signature=signature,
        )


def test_uri_extract_skips_empty_pairs_and_encode_rejects_whitespace_action() -> None:
    payload = {"x": 1}
    uri = encode_uri("login", payload)
    token = uri.split("d=", 1)[1]
    decorated = f"qid://login?&&d={token}"
    assert decode_uri(decorated, expected_action="login") == payload

    with pytest.raises(ValueError, match="Invalid Q-ID action"):
        encode_uri("bad action", payload)


class _SecretAttrOnlySigner:
    def __init__(self) -> None:
        self._secret_key_value = b""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    @property
    def secret_key(self) -> bytes:
        return self._secret_key_value

    @secret_key.setter
    def secret_key(self, value: bytes) -> None:
        self._secret_key_value = value

    def sign(self, msg: bytes) -> bytes:
        return b"sa:" + self._secret_key_value + b":" + msg


class _PrivateSkOnlySigner:
    _sk = b""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def sign(self, msg: bytes) -> bytes:
        return b"sk:" + self._sk + b":" + msg  # type: ignore[attr-defined]


class _RejectingSignatureFactory:
    def __call__(self, alg: str, secret_key: bytes | None = None):
        if secret_key is not None:
            raise TypeError("ctor kwargs unsupported")
        return _SecretAttrOnlySigner()


class _RejectingSignatureFactorySk:
    def __call__(self, alg: str, secret_key: bytes | None = None):
        if secret_key is not None:
            raise TypeError("ctor kwargs unsupported")
        return _PrivateSkOnlySigner()


class _VerifyBoom:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def verify(self, msg: bytes, sig: bytes, pub: bytes) -> bool:
        raise RuntimeError("boom")


class _VerifyOQS:
    class Signature:
        def __init__(self, alg: str, secret_key: bytes | None = None):
            pass

        def __enter__(self):
            return _VerifyBoom()

        def __exit__(self, exc_type, exc, tb):
            return False


class _SignReturnNone:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def sign(self, msg: bytes, priv: bytes | None = None):
        return None


class _NoneOQS:
    class Signature:
        def __init__(self, alg: str, secret_key: bytes | None = None):
            if secret_key is not None:
                raise TypeError("ctor kwargs unsupported")

        def __enter__(self):
            return _SignReturnNone()

        def __exit__(self, exc_type, exc, tb):
            return False


class _DummySig:
    def __init__(self, alg: str, secret_key: bytes | None = None):
        self.alg = alg
        self.secret_key = secret_key

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def sign(self, msg: bytes, priv: bytes | None = None) -> bytes:
        return b"sig:" + self.alg.encode("ascii") + b":" + msg

    def verify(self, msg: bytes, sig: bytes, pub: bytes) -> bool:
        return True


class _DummyOQS:
    Signature = _DummySig


def test_ml_dsa_secret_import_variants_and_verify_fail_closed() -> None:
    oqs_secret_attr = types.SimpleNamespace(Signature=_RejectingSignatureFactory())
    sig1 = pmd.sign_ml_dsa(oqs=oqs_secret_attr, msg=b"m", priv=b"k")
    assert sig1 == b"sa:k:m"

    oqs_private_sk = types.SimpleNamespace(Signature=_RejectingSignatureFactorySk())
    sig2 = pmd.sign_ml_dsa(oqs=oqs_private_sk, msg=b"m2", priv=b"k2")
    assert sig2 == b"sk:k2:m2"

    assert pmd.verify_ml_dsa(oqs=_VerifyOQS(), msg=b"m", sig=b"s", pub=b"p") is False


def test_falcon_none_signature_and_verify_fail_closed() -> None:
    with pytest.raises(RuntimeError, match="pqc_falcon signing failed"):
        pf.sign_falcon(oqs=_NoneOQS(), msg=b"m", priv=b"k")

    assert pf.verify_falcon(oqs=_VerifyOQS(), msg=b"m", sig=b"s", pub=b"p") is False


def test_pqc_backends_import_and_unsupported_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)

    class _ImportedOQS:
        Signature = _DummySig

    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "oqs":
            return _ImportedOQS
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    mod = pb._import_oqs()
    assert mod is _ImportedOQS
    assert pb.oqs is _ImportedOQS

    with pytest.raises(ValueError, match="Unsupported algorithm for liboqs"):
        pb.liboqs_sign("not-supported", b"m", b"k")

    with pytest.raises(ValueError, match="Unsupported algorithm for liboqs"):
        pb.liboqs_verify("not-supported", b"m", b"s", b"p")


def test_pqc_sign_decode_secret_key_guard() -> None:
    with pytest.raises(ValueError, match="missing secret_key"):
        ps._decode_secret_key(QIDKeyPair(algorithm="x", public_key="AA==", secret_key=""))


def test_pqc_verify_remaining_fail_closed_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="invalid base64url"):
        pv._b64url_decode(123)  # type: ignore[arg-type]

    assert pv.verify_pqc_login("bad", {"pqc_alg": pv.ML_DSA_ALGO}) is False
    assert pv.verify_pqc_login(login_payload={}, binding_env={"payload": "bad"}) is False

    monkeypatch.setattr(pv, "selected_backend", lambda: "liboqs")

    binding_payload = {
        "policy": "hybrid",
        "pqc_pubkeys": {"ml_dsa": _b64u(b"ml"), "falcon": _b64u(b"fa")},
    }
    login_payload = {
        "pqc_alg": pv.HYBRID_ALGO,
        "pqc_sig": {"ml_dsa": _b64u(b"s1"), "falcon": _b64u(b"s2")},
    }
    monkeypatch.setattr(pv, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    calls: list[str] = []

    def fake_verify(alg: str, msg: bytes, sig: bytes, pub: bytes) -> bool:
        calls.append(alg)
        return True

    monkeypatch.setattr(pv, "liboqs_verify", fake_verify)
    assert pv.verify_pqc_login(login_payload=login_payload, binding_env={"payload": binding_payload}) is True
    assert calls == [pv.ML_DSA_ALGO, pv.FALCON_ALGO]

    monkeypatch.setattr(
        pv,
        "enforce_no_silent_fallback_for_alg",
        lambda alg: (_ for _ in ()).throw(pv.PQCBackendError("x")),
    )
    assert pv.verify_pqc_login(
        login_payload={"pqc_alg": pv.FALCON_ALGO, "pqc_sig": _b64u(b"sig")},
        binding_env={"payload": {"policy": "falcon", "pqc_pubkeys": {"falcon": _b64u(b"pub")}}},
    ) is False


def test_protocol_branch_270_273_happy_and_binding_created_at_guards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import qid.protocol as pr

    request_payload = {
        "service_id": "svc",
        "callback_url": "https://cb",
        "nonce": "n1",
        "require": pr.REQUIRE_DUAL_PROOF,
        pr._BINDING_RESOLVER_KEY: lambda binding_id: {
            "payload": {"created_at": 1, "domain": "svc"},
            "binding_id": "bid",
        },
    }
    response_payload = {
        "type": "login_response",
        "service_id": "svc",
        "nonce": "n1",
        "require": pr.REQUIRE_DUAL_PROOF,
        "binding_id": "bid",
    }
    monkeypatch.setattr(pr, "verify_binding", lambda *a, **k: True)
    monkeypatch.setattr(pr._pqc_verify, "verify_pqc_login", lambda *a, **k: True)
    monkeypatch.setattr(pr, "verify_login_response", lambda *a, **k: True)
    assert pr.server_verify_login_response(
        request_payload,
        response_payload,
        "sig",
        generate_dev_keypair(),
    ) is True

    payload = {
        "domain": "svc",
        "purpose": "login",
        "challenge": "c",
        "created_at": "bad",
        "wallet_pubkey": "pk",
        "policy": "ml-dsa",
        "pqc_pubkeys": {"ml_dsa": _b64u(b"pub")},
    }
    env = {
        "payload": payload,
        "binding_id": binding.compute_binding_id({**payload, "created_at": 1}),
    }
    assert binding.verify_binding(env, generate_dev_keypair(), expected_domain="svc", now=10) is False

    payload2 = {
        "domain": "svc",
        "purpose": "login",
        "challenge": "c",
        "created_at": 1,
        "expires_at": "bad",
        "wallet_pubkey": "pk",
        "policy": "ml-dsa",
        "pqc_pubkeys": {"ml_dsa": _b64u(b"pub")},
    }
    env2 = {"payload": payload2, "binding_id": binding.compute_binding_id(payload2)}
    assert binding.verify_binding(env2, generate_dev_keypair(), expected_domain="svc", now=10) is False


def test_crypto_remaining_fail_closed_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    bad_sig_env = crypto._envelope_encode({"v": crypto._SIG_ENVELOPE_VERSION, "alg": pb.ML_DSA_ALGO})
    monkeypatch.setattr(crypto, "selected_backend", lambda: "liboqs", raising=False)
    assert crypto.verify_payload(
        {"x": 1},
        bad_sig_env,
        QIDKeyPair(algorithm=pb.ML_DSA_ALGO, public_key="AA==", secret_key="AA=="),
    ) is False

    kp = QIDKeyPair(algorithm=pb.HYBRID_ALGO, public_key="AA==", secret_key="AA==")
    hybrid_sig = crypto._envelope_encode(
        {"v": crypto._SIG_ENVELOPE_VERSION, "alg": pb.HYBRID_ALGO, "sigs": {pb.ML_DSA_ALGO: _b64u(b"a")}}
    )
    assert crypto.verify_payload(
        {"x": 1},
        hybrid_sig,
        kp,
        hybrid_container_b64=encode_container(
            build_container(kid="kid", ml_dsa_public_key="AA==", falcon_public_key="AA==")
        ),
    ) is False

    monkeypatch.setattr(crypto, "selected_backend", lambda: "liboqs", raising=False)
    monkeypatch.setattr(crypto, "enforce_no_silent_fallback_for_alg", lambda alg: None, raising=False)
    monkeypatch.setattr(
        crypto,
        "liboqs_verify",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        raising=False,
    )
    full_hybrid_sig = crypto._envelope_encode(
        {
            "v": crypto._SIG_ENVELOPE_VERSION,
            "alg": pb.HYBRID_ALGO,
            "sigs": {pb.ML_DSA_ALGO: _b64u(b"a"), pb.FALCON_ALGO: _b64u(b"b")},
        }
    )
    assert crypto.verify_payload(
        {"x": 1},
        full_hybrid_sig,
        kp,
        hybrid_container_b64=encode_container(
            build_container(kid="kid", ml_dsa_public_key="AA==", falcon_public_key="AA==")
        ),
    ) is False
