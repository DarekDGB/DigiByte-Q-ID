from __future__ import annotations

import qid.protocol as pr
import qid.pqc_sign as ps
from qid.crypto import DEV_ALGO, generate_keypair
from qid.pqc_backends import ML_DSA_ALGO


def test_build_dual_proof_login_response_stubs_pqc_and_signs_legacy() -> None:
    orig_sign = ps.sign_pqc_login_fields
    try:
        # Stub PQC signer: attaches deterministic fields without requiring oqs
        def stub(payload, *, pqc_alg, ml_dsa_keypair=None, falcon_keypair=None):
            payload["pqc_alg"] = pqc_alg
            payload["pqc_sig"] = "aa"

        ps.sign_pqc_login_fields = stub  # type: ignore[assignment]

        kp = generate_keypair(DEV_ALGO)

        req = pr.build_login_request_payload("example.com", "n1", "https://cb")
        req["require"] = pr.REQUIRE_DUAL_PROOF

        resp, sig = pr.build_dual_proof_login_response(
            request_payload=req,
            address="ADDR",
            pubkey="PUB",
            legacy_keypair=kp,
            binding_id="BIND123",
            pqc_alg=ML_DSA_ALGO,
            ml_dsa_keypair=kp,
        )

        assert resp["require"] == pr.REQUIRE_DUAL_PROOF
        assert resp["binding_id"] == "BIND123"
        assert resp["pqc_alg"] == ML_DSA_ALGO
        assert resp["pqc_sig"] == "aa"
        assert isinstance(sig, str) and sig != ""

    finally:
        ps.sign_pqc_login_fields = orig_sign  # type: ignore[assignment]
