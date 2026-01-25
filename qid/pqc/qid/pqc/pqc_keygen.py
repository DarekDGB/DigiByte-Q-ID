"""
Compatibility shim.

Some scripts refer to `qid.pqc.pqc_keygen`, while this repo implements keygen in
`qid.pqc.keygen_liboqs`. This module re-exports the keygen API so both imports
work without changing callers.
"""

from __future__ import annotations

from .keygen_liboqs import (  # noqa: F401
    PQCAlgorithmError,
    PQCBackendError,
    ALLOWED_FALCON_ALGS,
    ALLOWED_ML_DSA_ALGS,
    generate_falcon_keypair,
    generate_ml_dsa_keypair,
)
