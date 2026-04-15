from __future__ import annotations

from pathlib import Path


def test_repo_version_truth_locked_to_v1_0_2() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    security = Path("SECURITY.md").read_text(encoding="utf-8")
    contributing = Path("CONTRIBUTING.md").read_text(encoding="utf-8")
    code_of_conduct = Path("CODE_OF_CONDUCT.md").read_text(encoding="utf-8")

    assert 'version = "1.0.2"' in pyproject
    assert 'v1.0.2' in readme
    assert 'version-1.0.2-blue' in readme
    assert '## [1.0.2]' in changelog
    assert 'v1.0.2' in security
    assert 'v1.0.2' in contributing
    assert 'v1.0.2' in code_of_conduct


def test_package_surface_has_no_placeholder_language() -> None:
    package_init = Path("qid/__init__.py").read_text(encoding="utf-8")

    assert 'placeholder' not in package_init.lower()
    assert 'later we will' not in package_init.lower()
    assert 'real logic will be added step by step' not in package_init.lower()
