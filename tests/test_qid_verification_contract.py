from __future__ import annotations

import qid.crypto as c



def test_stub_verify_uses_public_material_not_secret_for_dev() -> None:
    signer = c.generate_keypair(c.DEV_ALGO)
    payload = {"x": 1}
    sig = c.sign_payload(payload, signer)

    verifier = c.QIDKeyPair(
        algorithm=signer.algorithm,
        public_key=signer.public_key,
        secret_key=c._b64encode(b"wrong-secret-material"),
    )

    assert c.verify_payload(payload, sig, verifier) is True



def test_stub_verify_fails_when_public_material_changes_even_if_secret_matches() -> None:
    signer = c.generate_keypair(c.DEV_ALGO)
    payload = {"x": 1}
    sig = c.sign_payload(payload, signer)

    wrong_pub = c.generate_keypair(c.DEV_ALGO).public_key
    verifier = c.QIDKeyPair(
        algorithm=signer.algorithm,
        public_key=wrong_pub,
        secret_key=signer.secret_key,
    )

    assert c.verify_payload(payload, sig, verifier) is False



def test_hybrid_stub_signature_shape_rejects_extra_components() -> None:
    kp = c.generate_keypair(c.HYBRID_ALGO)
    env = c._envelope_encode(
        {
            "v": 1,
            "alg": c.HYBRID_ALGO,
            "sigs": {
                c.ML_DSA_ALGO: c._b64encode(b"a"),
                c.FALCON_ALGO: c._b64encode(b"b"),
                "extra": c._b64encode(b"c"),
            },
        }
    )

    assert c.verify_payload({"x": 1}, env, kp) is False



def test_hybrid_backend_signature_shape_rejects_extra_components(monkeypatch) -> None:
    import qid.pqc_backends as pb
    from qid.hybrid_key_container import build_container, encode_container

    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda _alg: None)
    monkeypatch.setattr(pb, "liboqs_verify", lambda *_a, **_k: True)

    container = build_container("kid1", c._b64encode(b"mlpub"), c._b64encode(b"fapub"))
    container_b64 = encode_container(container)
    dummy = c.QIDKeyPair(algorithm=c.HYBRID_ALGO, public_key=c._b64encode(b"p"), secret_key=c._b64encode(b"s"))

    env = c._envelope_encode(
        {
            "v": 1,
            "alg": c.HYBRID_ALGO,
            "sigs": {
                c.ML_DSA_ALGO: "AAEC",
                c.FALCON_ALGO: "AAEC",
                "extra": "AAEC",
            },
        }
    )

    assert c.verify_payload({"x": 1}, env, dummy, hybrid_container_b64=container_b64) is False



def test_stub_sign_hybrid_without_public_uses_derived_public_material() -> None:
    secret = b"A" * 64
    sigs = c._stub_sign_hybrid(b"m", secret)
    public = c._b64decode(c.generate_keypair(c.HYBRID_ALGO).public_key)
    assert set(sigs.keys()) == {c.ML_DSA_ALGO, c.FALCON_ALGO}
    assert isinstance(sigs[c.ML_DSA_ALGO], bytes)
    assert isinstance(sigs[c.FALCON_ALGO], bytes)


def test_hybrid_stub_signature_shape_rejects_non_string_component_after_filter() -> None:
    kp = c.generate_keypair(c.HYBRID_ALGO)
    env = c._envelope_encode(
        {
            "v": 1,
            "alg": c.HYBRID_ALGO,
            "sigs": {
                c.ML_DSA_ALGO: c._b64encode(b"a"),
                c.FALCON_ALGO: 123,
            },
        }
    )

    assert c.verify_payload({"x": 1}, env, kp) is False
