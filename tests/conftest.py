import os
import pytest


@pytest.fixture(autouse=True)
def _isolate_qid_pqc_backend_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Ensure tests do not leak QID_PQC_BACKEND between runs.

    Default behavior (CI-safe):
    - No PQC backend selected unless a test explicitly opts in.
    """
    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
