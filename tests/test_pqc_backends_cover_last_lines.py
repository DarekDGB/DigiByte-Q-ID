from __future__ import annotations

import builtins
from unittest.mock import patch

import pytest

import qid.pqc_backends as pb


def test_import_oqs_none_return_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "oqs":
            return None
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        with pytest.raises(pb.PQCBackendError, match="oqs import returned None"):
            pb._import_oqs()


def test_import_oqs_real_import_success_path_sets_cached_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QID_PQC_BACKEND", "liboqs")
    monkeypatch.setattr(pb, "oqs", pb._OQS_UNSET, raising=False)

    class FakeOQS:
        class Signature:
            def __init__(self, *args, **kwargs):
                pass

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "oqs":
            return FakeOQS
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        mod = pb._import_oqs()

    assert mod is FakeOQS
    assert pb.oqs is FakeOQS
