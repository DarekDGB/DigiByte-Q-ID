from __future__ import annotations

import qid.crypto as crypto
import qid.pqc_backends as pb
from qid.crypto import QIDKeyPair
from qid.hybrid_key_container import build_container, encode_container


def test_verify_payload_liboqs_single_rejects_non_string_sig(monkeypatch) -> None:
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    sig_env = crypto._envelope_encode(
        {"v": crypto._SIG_ENVELOPE_VERSION, "alg": pb.ML_DSA_ALGO, "sig": 123}
    )
    keypair = QIDKeyPair(
        algorithm=pb.ML_DSA_ALGO,
        public_key="AA==",
        secret_key="AA==",
    )

    assert crypto.verify_payload({"x": 1}, sig_env, keypair) is False


def test_verify_payload_liboqs_hybrid_rejects_non_string_component_sig(monkeypatch) -> None:
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)

    sig_env = crypto._envelope_encode(
        {
            "v": crypto._SIG_ENVELOPE_VERSION,
            "alg": pb.HYBRID_ALGO,
            "sigs": {pb.ML_DSA_ALGO: "AA", pb.FALCON_ALGO: 123},
        }
    )
    keypair = QIDKeyPair(
        algorithm=pb.HYBRID_ALGO,
        public_key="AA==",
        secret_key="AA==",
    )
    hybrid_container_b64 = encode_container(
        build_container(
            kid="kid",
            ml_dsa_public_key="AA==",
            falcon_public_key="AA==",
        )
    )

    assert (
        crypto.verify_payload(
            {"x": 1},
            sig_env,
            keypair,
            hybrid_container_b64=hybrid_container_b64,
        )
        is False
    )


def test_verify_payload_liboqs_single_generic_exception_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(pb, "selected_backend", lambda: "liboqs")
    monkeypatch.setattr(pb, "enforce_no_silent_fallback_for_alg", lambda alg: None)
    monkeypatch.setattr(
        pb,
        "liboqs_verify",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    sig_env = crypto._envelope_encode(
        {"v": crypto._SIG_ENVELOPE_VERSION, "alg": pb.ML_DSA_ALGO, "sig": "AA"}
    )
    keypair = QIDKeyPair(
        algorithm=pb.ML_DSA_ALGO,
        public_key="AA==",
        secret_key="AA==",
    )

    assert crypto.verify_payload({"x": 1}, sig_env, keypair) is False
