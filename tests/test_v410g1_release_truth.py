from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import re
import tomllib


ROOT = Path(__file__).resolve().parents[1]
STATUS = "docs/RELEASES/V4_10_G1_RELEASE_TRUTH.md"
COPY_PATHS = (
    "README.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "docs/qid-v1.1.0-release-plan.md",
    STATUS,
    "tests/test_v410g1_release_truth.py",
)


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_g1_package_version_is_separate_from_historical_tag_and_shield() -> None:
    project = tomllib.loads(_text("pyproject.toml"))["project"]
    assert project["name"] == "digibyte-q-id"
    assert project["version"] == "1.1.0"
    assert project["authors"] == [{"name": "DarekDGB"}]
    status = _text(STATUS)
    assert "Deliberate no-bump" in status
    assert "Number unassigned" in status
    assert "4b753030bbf0a267931389c27f01bd05a3afc407" in status
    assert "eceb0e7e7a291a945a0c8063139474937796171f" in status
    for path in (ROOT / "qid").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert not any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
            and node.id in {"__version__", "server_version"}
            for node in ast.walk(tree)
        ), f"new version surface needs reconciliation: {path}"
    plan = _text("docs/qid-v1.1.0-release-plan.md")
    assert "historical release plan; v1.1.0 tag exists" in plan
    assert "tag still pending" not in plan
    assert "does not inherit the Shield `v4.0.0` release number" in _text("README.md")


def test_g1_keeps_frozen_manifests_contract_and_workflows_exact() -> None:
    expected = {
        "pyproject.toml": "6083a6c11a6d19bdf574f6f2ce6d30ed4d85547a2d61aaa1440a8e35f9b53b50",
        "contracts/manifest_v0_1.json": "05ddae6f002a9de7804776bbb2f46fbf7f7fdfb82595c3121d16d0f08a6601ae",
        "contracts/qid_shield_v4_compatibility_manifest_v1.json": "e193e6f166c091d98c46a942b3f178ba81bc590f7349be3b540631da41bbe937",
        "docs/CONTRACTS/QID_SHIELD_V4_CRYPTO_ALIGNMENT.md": "55078028534ebf2d8312b59a9d712053b2e97ebbc56da3b810ce0608f86efdee",
        "tests/test_qid_shield_v4_compatibility_lock.py": "53f7bb86a4c528e2e72825f5b4edf902ac0963b3c1662034175f78d8f8a1ea2f",
        ".github/workflows/tests.yml": "a41ae9e6d76f70a960ebf626ce2c2d27610a36e324adc1deaac551e5ae8789d3",
        ".github/workflows/pqc-optional-liboqs.yml": "413c6eed597357320f00f9b6e36afacfe27b5eef001280805cf25cc7ef869b59",
        "THIRD_PARTY_NOTICES.md": "b35cea6e9182c2df9aa12f66285cd245b5ce5aff876819c2be64d216ae377c86",
    }
    for relative, digest in expected.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == digest


def test_g1_public_claims_retain_identity_and_execution_boundaries() -> None:
    for relative in ("README.md", "SECURITY.md", STATUS):
        text = " ".join(_text(relative).split())
        assert "not secure PQC" in text
        assert "verify Shield cryptography or grant execution authority" in text
        assert "AdamantineOS" in text and "fail-closed" in text
        assert "qid-canonical-json-v1" in text
        assert "adamantine-qid-canonical-json-v1" in text
        assert "QID_SHIELD_V4_CRYPTO_ALIGNMENT.md" in text
        assert "no exact node-ID and zero-skip guard" in text
        if relative == "SECURITY.md":
            non_goals = _text(relative).split("Q-ID does NOT:\n", 1)[1].split("\nThe ", 1)[0]
            assert "- verify Shield cryptography or grant execution authority\n" in non_goals
        else:
            assert "Q-ID does not verify Shield cryptography or grant execution authority" in text
    assert "Guardian v3 auth bridge is not a Shield receipt verifier" in _text("README.md")


def test_g1_test_evidence_distinguishes_skips_coverage_and_pending_gates() -> None:
    config = tomllib.loads(_text("pyproject.toml"))
    assert config["tool"]["coverage"]["run"]["branch"] is True
    assert config["tool"]["coverage"]["report"]["fail_under"] == 100
    status = " ".join(_text(STATUS).split())
    assert "625 passed, 12 expected optional-OQS skips" in status
    assert "1662/1662, 100%" in status and "702/702, 100%" in status
    assert "6 passed" in status
    assert "post-commit CI and fresh-ZIP gates remain pending" in status
    assert "A green run alone does not prove every intended native node executed" in status
    readme = " ".join(_text("README.md").split())
    assert "625 passed, 12 expected optional-OQS skips" in readme
    assert "1662/1662 statements and 702/702 branches" in readme
    assert "CI-passing-brightgreen" not in readme


def test_g1_release_documents_resolve_repository_links() -> None:
    checked = 0
    for relative in COPY_PATHS:
        if not relative.endswith(".md"):
            continue
        path = ROOT / relative
        for target in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if target.startswith(("https://", "http://", "#", "mailto:")):
                continue
            resolved = (path.parent / target.split("#", 1)[0]).resolve()
            resolved.relative_to(ROOT.resolve())
            assert resolved.is_file(), f"broken release link: {relative}: {target}"
            checked += 1
    assert checked >= 9


def test_g1_copy_files_are_ascii_lf_without_transfer_damage() -> None:
    for relative in COPY_PATHS:
        data = (ROOT / relative).read_bytes()
        assert data.isascii(), f"non-ASCII copy file: {relative}"
        assert data.endswith(b"\n") and b"\r" not in data and b"\x00" not in data
        assert all(byte in (9, 10) or 32 <= byte <= 126 for byte in data)
        for line in data.decode("ascii").splitlines():
            assert line == line.rstrip(" \t"), f"trailing whitespace: {relative}"
