def verify_falcon(*, oqs: Any, msg: bytes, sig: bytes, pub: bytes, oqs_alg: str | None = None) -> bool:
    """Falcon verify — fail closed."""
    alg = oqs_alg or "Falcon-512"
    verifier = None
    try:
        verifier = oqs.Signature(alg)

        # Support both newer python-oqs (context manager) and the simple
        # Signature stubs used in tests.
        if hasattr(verifier, "__enter__") and hasattr(verifier, "__exit__"):
            with verifier as v:
                return bool(v.verify(msg, sig, pub))

        return bool(verifier.verify(msg, sig, pub))
    except Exception:
        return False
    finally:
        try:
            del verifier
        except Exception:
            pass
