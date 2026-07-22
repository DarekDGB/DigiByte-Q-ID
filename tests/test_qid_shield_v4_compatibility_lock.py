from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tomllib
from typing import Any

import pytest

from qid.algorithms import (
    DEV_ALGO,
    FALCON_ALGO,
    HYBRID_ALGO,
    LEGACY_HYBRID_ALGO,
    ML_DSA_ALGO,
    normalize_alg,
)
from qid.canonical_profiles import (
    ADAMANTINE_QID_CANONICAL_JSON_V1,
    QID_CANONICAL_JSON_V1,
)
import qid.pqc_backends as pqc_backends
from qid.pqc import keygen_liboqs


REPO_ROOT = Path(__file__).resolve().parents[1]
COMPATIBILITY_MANIFEST_PATH = (
    REPO_ROOT / "contracts" / "qid_shield_v4_compatibility_manifest_v1.json"
)
HISTORICAL_MANIFEST_PATH = REPO_ROOT / "contracts" / "manifest_v0_1.json"
ALIGNMENT_PATH = (
    REPO_ROOT / "docs" / "CONTRACTS" / "QID_SHIELD_V4_CRYPTO_ALIGNMENT.md"
)
INDEX_PATH = REPO_ROOT / "docs" / "CONTRACTS" / "INDEX.md"

ALIGNMENT_SHA256 = "55078028534ebf2d8312b59a9d712053b2e97ebbc56da3b810ce0608f86efdee"
INDEX_SHA256 = "0783664a29771c9520727e686580432d06b1ee90daa64c7283dcc25d2a0758b6"

FORBIDDEN_RUNTIME_MODULE_ROOTS = frozenset(
    {
        "adn_v2",
        "adn_v3",
        "dgb_wallet_guardian",
        "dqsnetwork",
        "qwg",
        "sentinel_ai_v2",
        "shield_orchestrator",
    }
)

FORBIDDEN_DISTRIBUTIONS = frozenset(
    {
        "dgb-quantum-shield-orchestrator",
        "dgb-quantum-wallet-guard",
        "dgb-wallet-guardian",
        "dqsnetwork",
        "digibyte-adn",
        "digibyte-quantum-shield-network",
        "dgb-sentinel-ai",
        "adn-v2",
        "adn-v3",
        "qwg",
        "sentinel-ai-v2",
        "shield-orchestrator",
    }
)

COMPATIBILITY_PATHS = (
    "docs/CONTRACTS/QID_SHIELD_V4_CRYPTO_ALIGNMENT.md",
    "docs/CONTRACTS/INDEX.md",
)

HISTORICAL_PATHS = (
    "contracts/api_surface_v0_1.json",
    "contracts/adamantine_qid_evidence_v2.json",
    "docs/CONTRACTS/CI_AND_CONTRACTS.md",
    "docs/CONTRACTS/CANONICAL_JSON_PROFILES.md",
    "docs/CONTRACTS/CONTRACT_QID_VERIFICATION.md",
    "docs/CONTRACTS/INDEX.md",
    "docs/CONTRACTS/LOCKED.md",
    "docs/CONTRACTS/PQC_MODEL.md",
    "docs/CONTRACTS/QID_SPEC_v0_1.md",
    "docs/CONTRACTS/TEST_TIERS.md",
    "docs/CONTRACTS/THREAT_MODEL.md",
    "docs/CONTRACTS/crypto_envelope_v1.md",
    "docs/CONTRACTS/hybrid_key_container_v1.md",
    "docs/CONTRACTS/login_payloads_v1.md",
    "docs/CONTRACTS/protocol_messages_v1.md",
    "docs/CONTRACTS/qid_uri_scheme_v1.md",
    "docs/CONTRACTS/registration_payload_v1.md",
)

HISTORICAL_UNCHANGED_HASHES = {
    "contracts/api_surface_v0_1.json": (
        "a4309809a1707556677ec5903cf3ec610cfa28882a74221bb70222649d7a47c8"
    ),
    "contracts/adamantine_qid_evidence_v2.json": (
        "2e57d3efb3413f7fa4ac5dcad2152b728c1dc99d47e8bbf7da9b63fdc711ab9e"
    ),
    "docs/CONTRACTS/CI_AND_CONTRACTS.md": (
        "c98ea43df942d00d17ff6b15a71cb7b82bb195e85750119636e1d0af3ff90362"
    ),
    "docs/CONTRACTS/CANONICAL_JSON_PROFILES.md": (
        "c991c7001eccfb353fe202eb66b376bbfd36f985d1912c5aa6ab3eee7d0b34f1"
    ),
    "docs/CONTRACTS/CONTRACT_QID_VERIFICATION.md": (
        "2471864d68246ee84c237d443584b4b1be3b14bcd1f792f71e66105a9072c755"
    ),
    "docs/CONTRACTS/LOCKED.md": (
        "90e9576d0f36d1bb8d51796bdc0be2f1a9db11b4baf80ae87a74b2ac4548dccd"
    ),
    "docs/CONTRACTS/PQC_MODEL.md": (
        "e1f4efa19856aef20aff2f6b6be62ac931cbf665251c0c911f2708ca1c805d63"
    ),
    "docs/CONTRACTS/QID_SPEC_v0_1.md": (
        "525e4e8564043098249db773b3b502fcc3185bdd791905cf78ed681bca9b15df"
    ),
    "docs/CONTRACTS/TEST_TIERS.md": (
        "231b33db3bbb23680c0113e4741946440de1ce5b9b7fcb85f7ab7e2ad86581dd"
    ),
    "docs/CONTRACTS/THREAT_MODEL.md": (
        "0a3ad20f0dd6c948ce86335cb0d791b832843ab5a63caf6b2f4238fa9217f735"
    ),
    "docs/CONTRACTS/crypto_envelope_v1.md": (
        "7bcb5e01824903e7a2c9cf697fe10eea116b1187735bc82ce33fc6391e9249cc"
    ),
    "docs/CONTRACTS/hybrid_key_container_v1.md": (
        "288a8eb263010a442487b7ffd9a5c45c3ecb059873cbd918482b7e5f69ecd69d"
    ),
    "docs/CONTRACTS/login_payloads_v1.md": (
        "84bb3d30f9018673517f6295d87e3b9d0a59e78b4ec064425af90736bab95faf"
    ),
    "docs/CONTRACTS/protocol_messages_v1.md": (
        "a36b8d3d92359cfee92add3af368589d9e793d28d64ad1b22cf024e90bdc4400"
    ),
    "docs/CONTRACTS/qid_uri_scheme_v1.md": (
        "185ca11d47990f3e8ac669ade2047291a5cdf46a756873b728d02453ac5862d2"
    ),
    "docs/CONTRACTS/registration_payload_v1.md": (
        "49a6c1842108e7569bcb0a1f9d3e22cd232cc6379636b8c276fc79ce2592c37d"
    ),
}

CONTROLLED_PATHS = (
    "contracts/manifest_v0_1.json",
    "contracts/qid_shield_v4_compatibility_manifest_v1.json",
    "docs/CONTRACTS/INDEX.md",
    "docs/CONTRACTS/QID_SHIELD_V4_CRYPTO_ALIGNMENT.md",
    "tests/test_qid_shield_v4_compatibility_lock.py",
)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _load_strict_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_bytes().decode("utf-8", errors="strict"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("manifest root must be an object")
    return value


def _sha256_bytes(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _regular_manifest_path(root: Path, raw_path: object) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("manifest path must be a non-empty string")
    if "\\" in raw_path or re.match(r"^[A-Za-z]:", raw_path):
        raise ValueError("manifest path must be repository-relative POSIX")

    relative = PurePosixPath(raw_path)
    if (
        relative.is_absolute()
        or relative.as_posix() != raw_path
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("unsafe manifest path")

    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("manifest path must not traverse a symlink")

    try:
        current.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (FileNotFoundError, ValueError) as exc:
        raise ValueError("manifest path escapes the repository or is missing") from exc

    if not current.is_file() or not stat.S_ISREG(current.stat().st_mode):
        raise ValueError("manifest path must identify a regular file")
    return current


def _require_unique_paths(paths: list[str]) -> None:
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate manifest path")
    if len(paths) != len({path.casefold() for path in paths}):
        raise ValueError("case-colliding manifest path")


def _manifest_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("manifest files must be an array")
    if not all(isinstance(entry, dict) for entry in files):
        raise ValueError("manifest entries must be objects")
    return files


def test_strict_manifest_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"version":"v1","nested":{"path":"a","path":"b"}}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key: path"):
        _load_strict_json(duplicate)


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "/absolute.txt",
        "../escape.txt",
        "docs/../escape.txt",
        "docs\\escape.txt",
        "C:/absolute.txt",
        "docs//file.txt",
        "docs/./file.txt",
    ],
)
def test_manifest_path_guard_rejects_unsafe_paths(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    with pytest.raises(ValueError):
        _regular_manifest_path(tmp_path, unsafe_path)


def test_manifest_path_guard_rejects_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("target\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="must not traverse a symlink"):
        _regular_manifest_path(tmp_path, "link.txt")


def test_manifest_inventory_rejects_duplicates_and_case_collisions() -> None:
    with pytest.raises(ValueError, match="duplicate manifest path"):
        _require_unique_paths(["docs/a.md", "docs/a.md"])
    with pytest.raises(ValueError, match="case-colliding manifest path"):
        _require_unique_paths(["docs/a.md", "DOCS/A.md"])


def test_compatibility_manifest_has_exact_safe_inventory_and_hashes() -> None:
    manifest = _load_strict_json(COMPATIBILITY_MANIFEST_PATH)

    assert list(manifest) == ["version", "hash_algorithm", "files"]
    assert manifest["version"] == "v1"
    assert manifest["hash_algorithm"] == "sha256"

    entries = _manifest_entries(manifest)
    assert entries == [
        {"path": COMPATIBILITY_PATHS[0], "sha256": ALIGNMENT_SHA256},
        {"path": COMPATIBILITY_PATHS[1], "sha256": INDEX_SHA256},
    ]

    paths = [entry["path"] for entry in entries]
    _require_unique_paths(paths)
    assert COMPATIBILITY_MANIFEST_PATH.relative_to(REPO_ROOT).as_posix() not in paths

    for entry in entries:
        assert list(entry) == ["path", "sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
        file_path = _regular_manifest_path(REPO_ROOT, entry["path"])
        assert _sha256_bytes(file_path) == entry["sha256"]


def test_historical_manifest_remains_exact_selective_inventory() -> None:
    historical = _load_strict_json(HISTORICAL_MANIFEST_PATH)
    compatibility = _load_strict_json(COMPATIBILITY_MANIFEST_PATH)

    assert list(historical) == ["version", "frozen_at_tag", "files"]
    assert historical["version"] == "v0.1"
    assert historical["frozen_at_tag"] == "v1.0.2-contracts-locked"

    entries = _manifest_entries(historical)
    assert all(list(entry) == ["path", "sha256"] for entry in entries)
    paths = [entry["path"] for entry in entries]
    assert tuple(paths) == HISTORICAL_PATHS
    _require_unique_paths(paths)

    assert COMPATIBILITY_PATHS[0] not in paths
    assert COMPATIBILITY_MANIFEST_PATH.relative_to(REPO_ROOT).as_posix() not in paths

    by_path = {entry["path"]: entry["sha256"] for entry in entries}
    assert {
        path: digest
        for path, digest in by_path.items()
        if path != "docs/CONTRACTS/INDEX.md"
    } == HISTORICAL_UNCHANGED_HASHES
    assert by_path["docs/CONTRACTS/INDEX.md"] == INDEX_SHA256

    compatibility_by_path = {
        entry["path"]: entry["sha256"]
        for entry in _manifest_entries(compatibility)
    }
    assert compatibility_by_path["docs/CONTRACTS/INDEX.md"] == INDEX_SHA256

    for entry in entries:
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
        file_path = _regular_manifest_path(REPO_ROOT, entry["path"])
        assert _sha256_bytes(file_path) == entry["sha256"]


def test_qid_runtime_mapping_and_crypto_agility_are_exact(monkeypatch: Any) -> None:
    assert DEV_ALGO == "dev-hmac-sha256"
    assert ML_DSA_ALGO == "pqc-ml-dsa"
    assert FALCON_ALGO == "pqc-falcon"
    assert HYBRID_ALGO == "pqc-hybrid-ml-dsa-falcon"
    assert LEGACY_HYBRID_ALGO == "hybrid-dev-ml-dsa"
    assert normalize_alg(LEGACY_HYBRID_ALGO) == HYBRID_ALGO

    assert QID_CANONICAL_JSON_V1.name == "qid-canonical-json-v1"
    assert (
        ADAMANTINE_QID_CANONICAL_JSON_V1.name
        == "adamantine-qid-canonical-json-v1"
    )

    assert pqc_backends._OQS_ALG_BY_QID == {
        ML_DSA_ALGO: "ML-DSA-44",
        FALCON_ALGO: "Falcon-512",
    }
    assert pqc_backends._oqs_alg_candidates_for(ML_DSA_ALGO) == (
        "ML-DSA-44",
        "Dilithium2",
    )
    assert pqc_backends._oqs_alg_candidates_for(FALCON_ALGO) == ("Falcon-512",)

    assert keygen_liboqs.ALLOWED_ML_DSA_ALGS == {
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
    }
    assert keygen_liboqs.ALLOWED_FALCON_ALGS == {"Falcon-512", "Falcon-1024"}

    monkeypatch.delenv("QID_PQC_BACKEND", raising=False)
    assert pqc_backends.selected_backend() is None
    assert pqc_backends.require_real_pqc() is False


def test_alignment_contract_locks_profiles_roles_and_claim_boundaries() -> None:
    alignment = ALIGNMENT_PATH.read_text(encoding="utf-8")
    normalized = " ".join(alignment.split())

    required_statements = (
        "Compatibility profile: `qid-shield-v4-compatibility-v1`",
        "Shield v4 produces cryptographically verifiable component-verdict and Orchestrator-receipt evidence.",
        "Q-ID's default execution mode is its deterministic CI-safe stub.",
        "Only explicit selection of `QID_PQC_BACKEND=liboqs` activates",
        "`pqc-ml-dsa` mapped to ML-DSA-44",
        "`pqc-falcon` mapped to Falcon-512",
        "`dev-hmac-sha256` | Deterministic development scaffold only | None",
        "`pqc-ml-dsa` | ML-DSA, formerly CRYSTALS-Dilithium | `ML-DSA-44`, with legacy backend label `Dilithium2` as a compatibility fallback",
        "`pqc-falcon` | Falcon-family signature evidence | `Falcon-512`",
        "`pqc-hybrid-ml-dsa-falcon` | Q-ID hybrid with strict AND semantics | `ML-DSA-44` and `Falcon-512`",
        "policy version: policy.v1",
        "required: classical-ed25519 + ml-dsa",
        "optional: fn-dsa",
        "Required classical | `classical-ed25519` | `classical-ed25519` | `rfc8032-ed25519-v1` | Ed25519",
        "Required PQC | `ml-dsa` | `pqc-ml-dsa` | `fips204-ml-dsa-65-v1` | ML-DSA-65",
        "Optional PQC evidence | `fn-dsa` | `pqc-fn-dsa` | `fips206-draft-falcon1024-v1` | Falcon-1024",
        "ML-DSA and FN-DSA/Falcon are separate signature directions.",
        "FN-DSA is based on Falcon.",
        "draft FN-DSA/Falcon-1024 evidence",
        "This contract does not claim final FIPS 206 standard proof.",
        "Q-ID `pqc-falcon` with Falcon-512 is not Shield `fn-dsa` with Falcon-1024.",
        "Q-ID `pqc-ml-dsa` with ML-DSA-44 is not Shield `ml-dsa` with ML-DSA-65.",
        "Parameter-set separation is not the trust boundary by itself.",
        "`shield_component_adn`",
        "`shield_component_dqsn`",
        "`shield_component_guardian_wallet`",
        "`shield_component_qwg`",
        "`shield_component_sentinel_ai`",
        "`shield_orchestrator`",
        "`qid-canonical-json-v1`",
        "`adamantine-qid-canonical-json-v1`",
        "`shield-v4-canon.v1`",
        "`DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1`",
        "`DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1`",
        "Optional FN-DSA evidence must never replace Ed25519 or ML-DSA",
        "Embedded policy is evidence only. It cannot weaken verifier-controlled local policy.",
        "make Shield decisions;",
        "sign Shield component verdicts;",
        "sign Shield Orchestrator receipts;",
        "verify Shield final authority;",
        "grant Shield execution approval;",
        "supply Shield trust-registry authority;",
        "upgrade a Shield `DENY` to `ALLOW`;",
        "override AdamantineOS policy;",
        "Shield v4 does not sign transactions, broadcast transactions, change DigiByte consensus, or grant final execution authority.",
        "It produces cryptographically verifiable decision evidence only.",
        "AdamantineOS remains the final fail-closed policy and execution boundary.",
        "A green run is Q-ID-only repository evidence, not guarded proof that required live nodes executed",
        "the workflow has no exact node-ID and zero-skip guard.",
        "It does not prove the guarded seven-repository Shield real-OQS boundary",
        "The dedicated manifest proves deterministic file integrity only.",
        "does not prove authorship, provenance, authentication, freshness, remote attestation, honest execution, or authority.",
    )
    for statement in required_statements:
        assert statement in normalized

    lowered = alignment.lower()
    assert "ecosystem-pre-v4-audit-lock" not in lowered
    assert "v4.2" not in lowered
    assert "planned" not in lowered

    forbidden_positive_claims = (
        "shield v4 signs transactions",
        "shield v4 can sign transactions",
        "shield v4 broadcasts transactions",
        "shield v4 can broadcast transactions",
        "shield v4 changes digibyte consensus",
        "shield v4 grants final execution authority",
        "q-id grants shield execution approval",
        "q-id grants shield final approval",
        "standard ci proves live liboqs",
        "q-id live-oqs is proven",
        "is final fips 206 compliant",
        "proves final fips 206",
    )
    for claim in forbidden_positive_claims:
        assert claim not in lowered


def _direct_import_names(tree: ast.AST) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names.append(node.module)
    return names


def _dynamic_import_names(tree: ast.AST, source_path: Path) -> list[str]:
    importlib_aliases = {"importlib"}
    import_module_aliases: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_aliases.add(alias.asname or alias.name)
                elif alias.name.startswith("importlib."):
                    importlib_aliases.add(alias.asname or "importlib")
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    import_module_aliases.add(alias.asname or alias.name)

    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_named_import = isinstance(node.func, ast.Name) and node.func.id in {
            "__import__",
            *import_module_aliases,
        }
        is_import_module = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"import_module", "__import__"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in importlib_aliases
        )
        if not (is_named_import or is_import_module):
            continue
        assert node.args, f"dynamic import without module in {source_path}"
        module = node.args[0]
        assert isinstance(module, ast.Constant) and isinstance(module.value, str), (
            f"non-literal dynamic import in {source_path}"
        )
        names.append(module.value)
    return names


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            'import importlib as il\nil.import_module("shield_orchestrator")\n',
            "shield_orchestrator",
        ),
        (
            'from importlib import import_module as loader\nloader("qwg")\n',
            "qwg",
        ),
        ('__import__("dgb_wallet_guardian")\n', "dgb_wallet_guardian"),
    ],
)
def test_dynamic_import_scan_covers_aliases(source: str, expected: str) -> None:
    tree = ast.parse(source)
    assert _dynamic_import_names(tree, Path("synthetic.py")) == [expected]


def _dependency_name(requirement: str) -> str:
    base = re.split(r"[<>=!~;@\[]", requirement, maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", base.strip().casefold())


@pytest.mark.parametrize(
    "requirement",
    [
        "DGB.Quantum.Wallet.Guard[crypto]>=1",
        "dgb_wallet_guardian",
        "DGB.Sentinel.AI; python_version >= '3.11'",
        "DigiByte.ADN @ https://invalid.example/package.whl",
        "QWG",
        "sentinel_ai_v2",
        "adn.v3",
    ],
)
def test_dependency_name_normalization_cannot_bypass_denylist(
    requirement: str,
) -> None:
    assert _dependency_name(requirement) in FORBIDDEN_DISTRIBUTIONS


def test_qid_runtime_has_no_shield_dependency_role_or_profile() -> None:
    forbidden_runtime_tokens = (
        "shield_component_",
        "shield_orchestrator",
        "shield-v4-canon.v1",
        "DGB-SHIELD-V4-",
        "fips204-ml-dsa-65-v1",
        "fips206-draft-falcon1024-v1",
    )

    runtime_paths = sorted((REPO_ROOT / "qid").rglob("*.py"))
    assert runtime_paths
    assert {
        REPO_ROOT / "qid" / "algorithms.py",
        REPO_ROOT / "qid" / "canonical_profiles.py",
        REPO_ROOT / "qid" / "pqc_backends.py",
        REPO_ROOT / "qid" / "pqc" / "keygen_liboqs.py",
    } <= set(runtime_paths)
    for source_path in runtime_paths:
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(source_path))
        imports = _direct_import_names(tree) + _dynamic_import_names(tree, source_path)
        for imported in imports:
            lowered = imported.casefold()
            module_root = lowered.split(".", 1)[0]
            assert module_root not in FORBIDDEN_RUNTIME_MODULE_ROOTS
            assert "shield" not in lowered
            assert "orchestrator" not in lowered
        for token in forbidden_runtime_tokens:
            assert token not in source

        lowered_source = source.casefold()
        for module_root in FORBIDDEN_RUNTIME_MODULE_ROOTS:
            assert module_root not in lowered_source

    pyproject = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    dependencies = list(pyproject["project"]["dependencies"])
    for values in pyproject["project"].get("optional-dependencies", {}).values():
        dependencies.extend(values)
    dependency_names = {_dependency_name(dependency) for dependency in dependencies}
    assert dependency_names.isdisjoint(FORBIDDEN_DISTRIBUTIONS)
    assert all("shield" not in name for name in dependency_names)


def test_contract_index_exposes_each_compatibility_lock_once() -> None:
    index = INDEX_PATH.read_text(encoding="utf-8")
    assert "### Shield v4 Compatibility Boundary" in index
    assert index.count("`QID_SHIELD_V4_CRYPTO_ALIGNMENT.md`") == 1
    assert (
        index.count("`contracts/qid_shield_v4_compatibility_manifest_v1.json`")
        == 1
    )


def test_controlled_files_are_ascii_lf_and_use_only_required_attribution() -> None:
    attribution_pattern = re.compile(
        r"\bDar" + r"ek[A-Za-z0-9_.-]*",
        flags=re.IGNORECASE,
    )

    for relative in CONTROLLED_PATHS:
        data = (REPO_ROOT / relative).read_bytes()
        text = data.decode("utf-8", errors="strict")
        assert data.isascii(), f"non-ASCII controlled file: {relative}"
        assert not data.startswith(b"\xef\xbb\xbf")
        assert b"\r" not in data
        assert b"\x00" not in data
        assert data.endswith(b"\n")
        for line in text.splitlines():
            stripped = line.rstrip(" \t")
            trailing = line[len(stripped) :]
            if relative.endswith(".md"):
                assert trailing in {"", "  "}
            else:
                assert trailing == ""
        for token in attribution_pattern.findall(text):
            assert token == "DarekDGB", f"unexpected attribution in {relative}"

    alignment = ALIGNMENT_PATH.read_text(encoding="utf-8")
    index = INDEX_PATH.read_text(encoding="utf-8")
    assert alignment.count("Author attribution: DarekDGB") == 1
    assert index.count("**Author:** DarekDGB") == 1

    alignment_headings = [
        line for line in alignment.splitlines() if line.startswith("#")
    ]
    assert len(alignment_headings) == len(set(alignment_headings))
