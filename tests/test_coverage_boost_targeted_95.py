import base64
import json
import pytest

import qid.pqc_backends as pb
import qid.pqc_verify as pv


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


# -------------------------
# qid/pqc_verify.py missing lines
# -------------------------

def test_pqc_verify_b64url_decode_rejects_whitespace_only() -> None:
    with pytest.raises(ValueError):
        pv._b64url_decode("   ")  # hits strip -> "" (lines around 28-29)


def test_pqc_verify_decode_pubkey_rejects_missing_dict() -> None:
    with pytest.raises(ValueError):
        pv._decode_pubkey({"pqc_pubkeys": "nope"}, "ml_dsa")  # hits "not a dict" branch (around 56)


def test_pqc_verify_select_signed_payload_rejects_non_mapping() -> None:
    binding = {"x": 1}
    login = {"pqc_payload": "nope"}  # not Mapping
    assert pv._select_signed_payload(binding, login) is None  # covers non-mapping branch (around 91)


def test_pqc_verify_verify_pqc_login_rejects_bad_call_shape() -> None:
    # kwargs mixed with args => fail-closed
    assert pv.verify_pqc_login({"x": 1}, {"y": 2}, login_payload={"z": 3}) is False  # covers call-shape guard


def test_pqc_verify_verify_pqc_login_rejects_missing_pqc_alg_even_if_backend_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    # Prevent real import attempts: inject dummy with Signature so selected_backend path proceeds
    monkeypatch.setattr(pb, "oqs", type("M", (), {"Signature": lambda *a, **k: None})(), raising=False)

    binding = {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": _b64u(b"a")}}
    login = {"pqc_sig": _b64u(b"sig")}  # missing pqc_alg => False (covers around 112)
    assert pv.verify_pqc_login(binding, login) is False


def test_pqc_verify_verify_pqc_login_rejects_policy_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", type("M", (), {"Signature": lambda *a, **k: None})(), raising=False)

    binding = {"policy": "falcon", "pqc_pubkeys": {"ml_dsa": _b64u(b"a")}}
    login = {"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": _b64u(b"sig")}
    assert pv.verify_pqc_login(binding, login) is False  # covers policy branch (around 116)


def test_pqc_verify_verify_pqc_login_handles_valueerror_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", type("M", (), {"Signature": lambda *a, **k: None})(), raising=False)

    # invalid b64url in pubkey triggers ValueError -> False (covers around 124 / 156-157)
    binding = {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": "%%%"}}
    login = {"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": _b64u(b"sig")}
    assert pv.verify_pqc_login(binding, login) is False


def test_pqc_verify_verify_pqc_login_unknown_backend_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "something-else")
    binding = {"policy": "ml-dsa", "pqc_pubkeys": {"ml_dsa": _b64u(b"a")}}
    login = {"pqc_alg": pb.ML_DSA_ALGO, "pqc_sig": _b64u(b"sig")}
    assert pv.verify_pqc_login(binding, login) is False  # covers unknown backend path (around 199)


# -------------------------
# qid/pqc_backends.py missing lines
# -------------------------

def test_pqc_backends_validate_oqs_module_rejects_missing_signature() -> None:
    with pytest.raises(pb.PQCBackendError):
        pb._validate_oqs_module(object())  # covers validator error (lines around 134-136)


def test_pqc_backends_enforce_unknown_backend_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "weird")
    with pytest.raises(pb.PQCBackendError):
        pb.enforce_no_silent_fallback_for_alg(pb.ML_DSA_ALGO)  # covers unknown backend branch (around 142)


def test_pqc_backends_liboqs_verify_returns_false_on_internal_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")

    class Mod:
        # looks valid for validator
        Signature = lambda *a, **k: None

    monkeypatch.setattr(pb, "oqs", Mod(), raising=False)

    # Force verify implementation to raise generic Exception so liboqs_verify falls through and returns False
    import qid.pqc.pqc_ml_dsa as ml
    monkeypatch.setattr(ml, "verify_ml_dsa", lambda **kw: (_ for _ in ()).throw(RuntimeError("boom")))

    assert pb.liboqs_verify(pb.ML_DSA_ALGO, b"m", b"s", b"p") is False  # covers exception->continue->False (around 208)


# -------------------------
# qid/crypto.py targeted lines (pure envelope + fail-closed)
# -------------------------

def test_crypto_verify_payload_rejects_non_object_envelope() -> None:
    from qid.crypto import verify_payload, generate_keypair, DEV_ALGO

    kp = generate_keypair(DEV_ALGO)
    # valid base64 but JSON is a list, not dict
    raw = json.dumps([1, 2, 3]).encode("utf-8")
    sig = base64.b64encode(raw).decode("ascii")
    assert verify_payload({"x": 1}, sig, kp) is False


def test_crypto_verify_payload_rejects_missing_sig_field() -> None:
    from qid.crypto import verify_payload, generate_keypair, DEV_ALGO

    kp = generate_keypair(DEV_ALGO)
    env = {"v": 1, "alg": DEV_ALGO}  # missing "sig"
    sig = base64.b64encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode("utf-8")).decode("ascii")
    assert verify_payload({"x": 1}, sig, kp) is False
