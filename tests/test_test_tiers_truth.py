from pathlib import Path


def test_main_ci_locks_100_percent_coverage() -> None:
    content = Path('.github/workflows/tests.yml').read_text(encoding='utf-8')
    assert '--cov-fail-under=100' in content
    assert 'name: tests' in content


def test_optional_pqc_workflow_remains_explicit() -> None:
    content = Path('.github/workflows/pqc-optional-liboqs.yml').read_text(encoding='utf-8')
    assert 'name: PQC Optional (liboqs real backend)' in content
    assert 'QID_PQC_BACKEND: liboqs' in content
    assert 'QID_PQC_TESTS: "1"' in content


def test_contract_docs_describe_two_test_tiers() -> None:
    ci_contract = Path('docs/CONTRACTS/CI_AND_CONTRACTS.md').read_text(encoding='utf-8')
    test_tiers = Path('docs/CONTRACTS/TEST_TIERS.md').read_text(encoding='utf-8')
    locked = Path('docs/CONTRACTS/LOCKED.md').read_text(encoding='utf-8')
    index = Path('docs/CONTRACTS/INDEX.md').read_text(encoding='utf-8')

    assert 'Tier 1 — Main deterministic baseline' in ci_contract
    assert 'Tier 2 — Optional real PQC backend proof' in ci_contract
    assert 'coverage gate `= 100%`' in ci_contract
    assert 'Tier 1 is the primary release gate.' in test_tiers
    assert 'Tier 2 is not a replacement for Tier 1.' in test_tiers
    assert 'Tier 1 deterministic coverage remains 100%' in locked
    assert '### Test Tiers' in index
