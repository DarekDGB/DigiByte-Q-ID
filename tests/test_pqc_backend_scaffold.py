import os
import pytest

from qid.crypto import ML_DSA_ALGO, generate_keypair, sign_payload
from qid.pqc_backends import PQCBackendError


def test_no_backend_selected_does_not_block_signing() -> None:
    os.environ.pop("QID_PQC_BACKEND", None)
    kp = generate_keypair(ML_DSA_ALGO)
    sig = sign_payload({"x": 1}, kp)
    assert isinstance(sig, str) and sig


def test_backend_selected_fails_closed_until_wired() -> None:
    os.environ["QID_PQC_BACKEND"] = "liboqs"
    kp = generate_keypair(ML_DSA_ALGO)
    with pytest.raises(PQCBackendError):
        sign_payload({"x": 1}, kp)
    os.environ.pop("QID_PQC_BACKEND", None)
