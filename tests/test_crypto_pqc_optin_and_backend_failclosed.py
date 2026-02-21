import base64
import importlib.util
import json
import types

import pytest

import qid.crypto as c
import qid.pqc_backends as pb
from qid.crypto import QIDKeyPair


def _env_sig(obj: dict) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def test_generate_keypair_optin_real_pqc_branch_via_fake_keygen(monkeypatch) -> None:
    # Hits crypto.py 158-165 (opt-in branch)
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setenv("QID_PQC_TESTS", "1")
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object() if name == "oqs" else None)

    fake_mod = types.SimpleNamespace(
        generate_ml_dsa_keypair=lambda name: (b"PUB", b"SK"),
        generate_falcon_keypair=lambda name: (b"FPUB", b"FSK"),
    )
    monkeypatch.setitem(__import__("sys").modules, "qid.pqc.keygen_liboqs", fake_mod)

    kp1 = c.generate_keypair(c.ML_DSA_ALGO)
    assert kp1.algorithm == c.ML_DSA_ALGO
    assert isinstance(base64.b64decode(kp1.public_key.encode("ascii")), bytes)

    kp2 = c.generate_keypair(c.FALCON_ALGO)
    assert kp2.algorithm == c.FALCON_ALGO


def test_generate_keypair_optin_branch_falls_back_on_exception(monkeypatch) -> None:
    # Hits crypto.py 166-168 (exception -> pass -> fallback stub)
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setenv("QID_PQC_TESTS", "1")
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object() if name == "oqs" else None)

    def boom(_name: str):
        raise RuntimeError("boom")

    fake_mod = types.SimpleNamespace(generate_ml_dsa_keypair=boom, generate_falcon_keypair=boom)
    monkeypatch.setitem(__import__("sys").modules, "qid.pqc.keygen_liboqs", fake_mod)

    kp = c.generate_keypair(c.ML_DSA_ALGO)
    assert kp.algorithm == c.ML_DSA_ALGO  # still that alg, but CI-safe stub


def test_verify_payload_backend_branch_rejects_non_string_sig(monkeypatch) -> None:
    # Hits crypto.py 268 (sig field wrong type)
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda _alg: None)
    monkeypatch.setattr(pb, "liboqs_verify", lambda *_a, **_k: True)

    kp = QIDKeyPair(algorithm=c.ML_DSA_ALGO, secret_key=c._b64encode(b"s" * 64), public_key=c._b64encode(b"p" * 32))
    sig_env = _env_sig({"v": "1", "alg": c.ML_DSA_ALGO, "sig": 123})  # wrong type
    assert c.verify_payload({"k": "v"}, sig_env, kp) is False


def test_verify_payload_backend_branch_hybrid_rejects_non_string_sigs(monkeypatch) -> None:
    # Hits crypto.py 286 (hybrid sig entries wrong type)
    from qid.hybrid_key_container import build_container, encode_container

    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda _alg: None)
    monkeypatch.setattr(pb, "liboqs_verify", lambda *_a, **_k: True)

    container = build_container("kid1", c._b64encode(b"mlpub"), c._b64encode(b"fapub"))
    container_b64 = encode_container(container.to_dict())

    kp = QIDKeyPair(algorithm=c.HYBRID_ALGO, secret_key=c._b64encode(b"s" * 64), public_key=c._b64encode(b"p" * 32))
    sig_env = _env_sig({"v": "1", "alg": c.HYBRID_ALGO, "sigs": {c.ML_DSA_ALGO: "AA==", c.FALCON_ALGO: 123}})
    assert c.verify_payload({"k": "v"}, sig_env, kp, hybrid_container_b64=container_b64) is False


def test_verify_payload_backend_branch_catches_generic_exception(monkeypatch) -> None:
    # Hits crypto.py 299-300 (except Exception -> False)
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda _alg: None)

    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(pb, "liboqs_verify", boom)

    kp = QIDKeyPair(algorithm=c.ML_DSA_ALGO, secret_key=c._b64encode(b"s" * 64), public_key=c._b64encode(b"p" * 32))
    sig_env = _env_sig({"v": "1", "alg": c.ML_DSA_ALGO, "sig": c._b64encode(b"x")})
    assert c.verify_payload({"k": "v"}, sig_env, kp) is False
