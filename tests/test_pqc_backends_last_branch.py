import qid.pqc_backends as pb


def test_enforce_no_silent_fallback_returns_when_backend_none():
    """
    Covers line 109:
    unsupported alg + backend None → return (no exception)
    """

    # ensure backend is None
    import os
    os.environ.pop("QID_PQC_BACKEND", None)

    # should NOT raise
    result = pb.enforce_no_silent_fallback_for_alg("not-supported")

    assert result is None
