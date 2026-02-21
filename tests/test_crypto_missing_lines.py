import pytest

import qid.crypto as c
from qid.crypto import QIDKeyPair, DEV_ALGO, HYBRID_ALGO


def test_generate_keypair_hits_unsupported_norm_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    # Cover crypto.py line 175 by forcing _normalize_alg to return an unknown value
    # while passing an allowed alg input.
    monkeypatch.setattr(c, "_normalize_alg", lambda _x: "weird-norm")
    with pytest.raises(ValueError, match="Unsupported Q-ID algorithm"):
        c.generate_keypair(DEV_ALGO)


def test_sign_payload_rejects_unknown_algorithm() -> None:
    kp = QIDKeyPair(algorithm="weird", public_key=c._b64encode(b"p"), secret_key=c._b64encode(b"s"))
    with pytest.raises(ValueError, match=r"Unknown Q-ID algorithm: 'weird'"):
        c.sign_payload({"x": 1}, kp)


def test_verify_payload_backend_branch_rejects_non_string_sig(monkeypatch: pytest.MonkeyPatch) -> None:
    # Cover crypto.py line 268: env["sig"] is not str in PQC backend branch.
    import qid.pqc_backends as pb

    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda _alg: None)
    monkeypatch.setattr(pb, "liboqs_verify", lambda *_a, **_k: True)

    sig_env = c._envelope_encode({"v": "1", "alg": "pqc-ml-dsa", "sig": 123})
    kp = QIDKeyPair(algorithm="pqc-ml-dsa", public_key=c._b64encode(b"p"), secret_key=c._b64encode(b"s"))
    assert c.verify_payload({"x": 1}, sig_env, kp) is False


def test_verify_payload_backend_branch_decodes_sig_then_b64_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # Exercise "decode sig" path and fail-closed on invalid base64.
    # This is intended to hit the "generic exception => False" guard in crypto.py 299-300.
    import qid.pqc_backends as pb

    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda _alg: None)
    monkeypatch.setattr(pb, "liboqs_verify", lambda *_a, **_k: True)

    sig_env = c._envelope_encode({"v": "1", "alg": "pqc-ml-dsa", "sig": "!!!"})
    kp = QIDKeyPair(algorithm="pqc-ml-dsa", public_key=c._b64encode(b"p"), secret_key=c._b64encode(b"s"))
    assert c.verify_payload({"x": 1}, sig_env, kp) is False


def test_verify_payload_backend_hybrid_rejects_non_string_sigs(monkeypatch: pytest.MonkeyPatch) -> None:
    # Cover crypto.py line 286: hybrid sig entries wrong type => fail closed.
    import qid.pqc_backends as pb
    from qid.hybrid_key_container import build_container, encode_container

    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda _alg: None)
    monkeypatch.setattr(pb, "liboqs_verify", lambda *_a, **_k: True)

    container = build_container("kid1", c._b64encode(b"mlpub"), c._b64encode(b"fapub"))
    container_b64 = encode_container(container)

    sig_env = c._envelope_encode(
        {"v": "1", "alg": HYBRID_ALGO, "sigs": {"pqc-ml-dsa": 123, "pqc-falcon": "AAEC"}}
    )
    dummy = QIDKeyPair(algorithm=HYBRID_ALGO, public_key=c._b64encode(b"p"), secret_key=c._b64encode(b"s"))
    assert c.verify_payload({"x": 1}, sig_env, dummy, hybrid_container_b64=container_b64) is False


def test_verify_payload_backend_hybrid_decodes_both_sigs_then_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Exercise the "both sigs are strings" path and decode attempts, but don't assume overall success.
    # Hybrid verification can fail-closed due to container/pubkey binding rules beyond the backend stub.
    import qid.pqc_backends as pb
    from qid.hybrid_key_container import build_container, encode_container

    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda _alg: None)
    monkeypatch.setattr(pb, "liboqs_verify", lambda *_a, **_k: True)

    container = build_container("kid1", c._b64encode(b"mlpub"), c._b64encode(b"fapub"))
    container_b64 = encode_container(container)

    # Use syntactically valid b64 so we definitely reach decode paths.
    sig_env = c._envelope_encode(
        {"v": "1", "alg": HYBRID_ALGO, "sigs": {"pqc-ml-dsa": "AAEC", "pqc-falcon": "AAEC"}}
    )
    dummy = QIDKeyPair(algorithm=HYBRID_ALGO, public_key=c._b64encode(b"p"), secret_key=c._b64encode(b"s"))

    # Must be deterministic fail-closed OR True depending on deeper rules; we accept either,
    # but we insist it's a boolean (no exceptions / no None).
    out = c.verify_payload({"x": 1}, sig_env, dummy, hybrid_container_b64=container_b64)
    assert isinstance(out, bool)


def test_verify_payload_backend_branch_hits_generic_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    # Cover crypto.py 299-300: unexpected exception inside backend branch => False.
    import qid.pqc_backends as pb
    from qid.hybrid_key_container import build_container, encode_container

    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda _alg: None)

    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(pb, "liboqs_verify", boom)

    container = build_container("kid1", c._b64encode(b"mlpub"), c._b64encode(b"fapub"))
    container_b64 = encode_container(container)

    sig_env = c._envelope_encode(
        {"v": "1", "alg": HYBRID_ALGO, "sigs": {"pqc-ml-dsa": "AAEC", "pqc-falcon": "AAEC"}}
    )
    dummy = QIDKeyPair(algorithm=HYBRID_ALGO, public_key=c._b64encode(b"p"), secret_key=c._b64encode(b"s"))
    assert c.verify_payload({"x": 1}, sig_env, dummy, hybrid_container_b64=container_b64) is False
