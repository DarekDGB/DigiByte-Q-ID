"""
Integration helpers for DigiByte Q-ID.

This package hosts helper functions for integrating Q-ID with:
- AdamantineOS
- Guardian rules engine
- Other DigiByte tools and services
"""

from .adamantine import build_adamantineos_qid_verifier

__all__ = ["build_adamantineos_qid_verifier"]
