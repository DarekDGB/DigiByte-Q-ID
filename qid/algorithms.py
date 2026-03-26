"""
Algorithm identifiers and normalization rules for DigiByte Q-ID.

Single source of truth for:
- public algorithm IDs
- legacy alias handling
- allowed algorithm set
"""

from __future__ import annotations


DEV_ALGO = "dev-hmac-sha256"
ML_DSA_ALGO = "pqc-ml-dsa"
FALCON_ALGO = "pqc-falcon"
HYBRID_ALGO = "pqc-hybrid-ml-dsa-falcon"

LEGACY_HYBRID_ALGO = "hybrid-dev-ml-dsa"

ALLOWED_ALGOS = {
    DEV_ALGO,
    ML_DSA_ALGO,
    FALCON_ALGO,
    HYBRID_ALGO,
    LEGACY_HYBRID_ALGO,
}


def normalize_alg(alg: str) -> str:
    if alg == LEGACY_HYBRID_ALGO:
        return HYBRID_ALGO
    return alg
