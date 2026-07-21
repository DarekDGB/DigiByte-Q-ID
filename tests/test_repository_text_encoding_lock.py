from __future__ import annotations

from pathlib import Path
import re
import tomllib
import unicodedata

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
TEXT_FILE_SUFFIXES = frozenset(
    {".json", ".lock", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"}
)
TEXT_FILE_NAMES = frozenset({".gitignore", "PKG-INFO"})
IGNORED_PATH_PARTS = frozenset(
    {
        ".git",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
    }
)
MOJIBAKE_LEAD_CHARACTERS = (
    "\u00c2",
    "\u00c3",
    "\u00e2",
    "\u00f0",
)
KNOWN_MOJIBAKE_SEQUENCES = (
    "\u00c2\u00a9",
    "\u00e2\u0086\u0092",
    "\u00e2\u0080\u0094",
    "\u00c3\u00a2\u00c2\u0080\u00c2\u0094",
    "\u00f0\u009f\u0094\u0090",
    "\u00ef\u00bb\u00bf",
)
BIDI_CONTROL_CHARACTERS = tuple(
    chr(codepoint)
    for codepoint in (
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
    )
)
REQUIRED_TEXT_PATHS = frozenset(
    {
        ".github/workflows/pqc-optional-liboqs.yml",
        ".github/workflows/tests.yml",
        ".gitignore",
        "LICENSE.md",
        "contracts/manifest_v0_1.json",
        "docs/CONTRACTS/CONTRACT_QID_VERIFICATION.md",
        "docs/CONTRACTS/protocol_messages_v1.md",
        "pyproject.toml",
        "qid/protocol.py",
        "tests/test_canonical_lock.py",
        "tests/test_repository_text_encoding_lock.py",
    }
)
ATTRIBUTION_TOKEN_PATTERN = re.compile(
    r"\bDar" + r"ek[A-Za-z0-9_.-]*",
    flags=re.IGNORECASE,
)
ATTRIBUTION_LINE_PATTERN = re.compile(
    r"^(?:(?:author(?:ship)?(?:\s+attribution)?|attribution|architect|"
    r"assistant|creator|maintainer|owner|contributor)s?\s*:|"
    r"copyright\s*(?:\(c\)|\u00a9)|\u00a9|"
    r"MIT(?: License| Licensed)?\s+(?:-|--|\u2014)\s+"
    r".+|"
    r"(?:created|developed|implemented|implementation|maintained|prepared|"
    r"written)\s+by\b)",
    flags=re.IGNORECASE,
)
ALLOWED_ATTRIBUTION_LINE_PATTERNS = (
    re.compile(
        r"^(?:Author|Authorship|Attribution|Architect|Assistant|Creator|"
        r"Maintainer|Owner|Contributor|Author attribution): DarekDGB$",
        flags=re.IGNORECASE,
    ),
    re.compile(
        r"^(?:Copyright \(c\)|\u00a9) (?:20[0-9]{2} )?DarekDGB"
        r"(?: MIT License)?$",
        flags=re.IGNORECASE,
    ),
    re.compile(
        r"^MIT(?: License)? (?:-|--|\u2014) "
        r"(?:Copyright \(c\)|\u00a9) 20[0-9]{2} DarekDGB$",
        flags=re.IGNORECASE,
    ),
    re.compile(
        r"^MIT Licensed (?:-|--|\u2014) DarekDGB$",
        flags=re.IGNORECASE,
    ),
    re.compile(
        r"^(?:Created|Developed|Implemented|Implementation|Maintained|Prepared|"
        r"Written) by:? DarekDGB$",
        flags=re.IGNORECASE,
    ),
)


def _is_runtime_liboqs_checkout_path(
    relative: Path,
    repository_root: Path,
) -> bool:
    if not relative.parts or relative.parts[0] != "liboqs":
        return False

    checkout = repository_root / "liboqs"
    git_directory = checkout / ".git"
    return (
        checkout.is_dir()
        and not checkout.is_symlink()
        and git_directory.is_dir()
        and not git_directory.is_symlink()
    )


def _repository_text_paths(repository_root: Path = REPO_ROOT) -> list[Path]:
    runtime_liboqs_checkout = repository_root / "liboqs"
    if runtime_liboqs_checkout.is_symlink():
        raise ValueError("top-level liboqs path must not be a symlink")

    paths: list[Path] = []
    for path in repository_root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(repository_root)
        if IGNORED_PATH_PARTS.intersection(relative.parts):
            continue
        if _is_runtime_liboqs_checkout_path(relative, repository_root):
            continue
        if path.suffix not in TEXT_FILE_SUFFIXES and path.name not in TEXT_FILE_NAMES:
            continue
        paths.append(path)
    return sorted(paths)


def _encoding_damage_reasons(text: str) -> set[str]:
    reasons: set[str] = set()
    if "\ufeff" in text:
        reasons.add("BOM")
    if "\x00" in text:
        reasons.add("NUL")
    if "\ufffd" in text:
        reasons.add("replacement character")
    if "\r" in text:
        reasons.add("non-LF newline")
    if any(
        (ord(character) < 0x20 and character not in "\t\n")
        or ord(character) == 0x7F
        for character in text
    ):
        reasons.add("C0 or DEL control")
    if any("\u0080" <= character <= "\u009f" for character in text):
        reasons.add("C1 control")
    if any(marker in text for marker in MOJIBAKE_LEAD_CHARACTERS):
        reasons.add("mojibake lead")
    if any(sequence in text for sequence in KNOWN_MOJIBAKE_SEQUENCES):
        reasons.add("known mojibake sequence")
    if any(character in text for character in BIDI_CONTROL_CHARACTERS):
        reasons.add("bidirectional control")
    if "\u2028" in text or "\u2029" in text:
        reasons.add("Unicode line separator")
    if any(unicodedata.category(character) == "Cf" for character in text):
        reasons.add("Unicode format control")
    if unicodedata.normalize("NFC", text) != text:
        reasons.add("non-NFC text")
    return reasons


def _normalized_attribution_line(line: str) -> str:
    plain = line.strip().rstrip("\\").replace("*", "").replace("`", "")
    if plain.startswith("<!--") and plain.endswith("-->"):
        plain = plain[4:-3].strip()
    plain = plain.lstrip("#>- ")
    return " ".join(plain.split())


def _is_first_party_attribution_line(line: str) -> bool:
    return ATTRIBUTION_LINE_PATTERN.search(_normalized_attribution_line(line)) is not None


def _is_allowed_first_party_attribution_line(line: str) -> bool:
    normalized = _normalized_attribution_line(line)
    return any(
        pattern.fullmatch(normalized)
        for pattern in ALLOWED_ATTRIBUTION_LINE_PATTERNS
    )


def test_repository_text_is_strict_utf8_and_transfer_safe() -> None:
    paths = _repository_text_paths()
    assert len(paths) >= 166
    relative_paths = {
        path.relative_to(REPO_ROOT).as_posix()
        for path in paths
    }
    assert REQUIRED_TEXT_PATHS <= relative_paths

    for path in paths:
        relative = path.relative_to(REPO_ROOT)
        try:
            text = path.read_bytes().decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            pytest.fail(f"invalid UTF-8 in {relative}: {exc}")

        reasons = _encoding_damage_reasons(text)
        assert not reasons, f"encoding damage in {relative}: {sorted(reasons)}"


def test_repository_scan_excludes_only_runtime_liboqs_checkout(
    tmp_path: Path,
) -> None:
    relative_text_paths = {
        "liboqs/LICENSE.txt",
        "docs/liboqs/LICENSE.txt",
        "tests/liboqs/LICENSE.txt",
        "liboqs-not/LICENSE.txt",
        "notes.txt",
    }
    for relative in relative_text_paths:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("text\n", encoding="utf-8")

    def scanned_paths() -> set[str]:
        return {
            path.relative_to(tmp_path).as_posix()
            for path in _repository_text_paths(tmp_path)
        }

    assert scanned_paths() == relative_text_paths

    git_marker = tmp_path / "liboqs" / ".git"
    git_marker.write_text("not a checkout directory\n", encoding="utf-8")
    assert scanned_paths() == relative_text_paths

    git_marker.unlink()
    git_marker.mkdir()
    assert scanned_paths() == relative_text_paths - {"liboqs/LICENSE.txt"}


def test_runtime_liboqs_checkout_marker_rejects_symlinks(tmp_path: Path) -> None:
    relative = Path("liboqs/LICENSE.txt")
    checkout = tmp_path / "liboqs"
    checkout_target = tmp_path / "checkout-target"
    (checkout_target / ".git").mkdir(parents=True)
    checkout.symlink_to(checkout_target, target_is_directory=True)
    assert not _is_runtime_liboqs_checkout_path(relative, tmp_path)
    with pytest.raises(ValueError, match="top-level liboqs path must not be a symlink"):
        _repository_text_paths(tmp_path)

    checkout.unlink()
    checkout.mkdir()
    (checkout / "LICENSE.txt").write_text("text\n", encoding="utf-8")
    git_target = tmp_path / "git-target"
    git_target.mkdir()
    (checkout / ".git").symlink_to(git_target, target_is_directory=True)
    assert not _is_runtime_liboqs_checkout_path(relative, tmp_path)
    assert relative in {
        path.relative_to(tmp_path)
        for path in _repository_text_paths(tmp_path)
    }


@pytest.mark.parametrize(
    "damaged",
    [
        "\u00c2\u00a9",
        "\u00e2\u0086\u0092",
        "\u00c3\u00a2\u00c2\u0080\u00c2\u0094",
        "\u00f0\u009f\u0094\u0090",
        "\u00ef\u00bb\u00bf",
        "\ufeff",
        "\ufffd",
        "\u0085",
        "\u202e",
        "\u2028",
        "\u2029",
        "\u00ad",
        "\u200b",
        "\u2060",
        "\x0b",
        "\x7f",
        "e\u0301",
        "line\r\n",
        "nul\x00byte",
    ],
)
def test_encoding_damage_detector_rejects_regression_samples(damaged: str) -> None:
    assert _encoding_damage_reasons(damaged)


@pytest.mark.parametrize(
    "clean",
    [
        "Copyright \u00a9 DarekDGB",
        "forward \u2192 reject",
        "rule \u2014 boundary",
        "Za\u017c\u00f3\u0142\u0107 g\u0119\u015bl\u0105 ja\u017a\u0144",
        "\u0141\u00f3d\u017a",
        "\U0001f510",
    ],
)
def test_encoding_damage_detector_accepts_valid_unicode(clean: str) -> None:
    assert _encoding_damage_reasons(clean) == set()


def test_repository_attribution_and_package_metadata_are_exact() -> None:
    license_lines = (REPO_ROOT / "LICENSE.md").read_text(encoding="utf-8").splitlines()
    assert license_lines[2] == "Copyright (c) 2025 DarekDGB"

    pyproject = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert pyproject["project"]["authors"] == [{"name": "DarekDGB"}]

    for path in _repository_text_paths():
        text = path.read_text(encoding="utf-8")
        for token in ATTRIBUTION_TOKEN_PATTERN.findall(text):
            assert token == "DarekDGB", f"unexpected attribution in {path}"

        if path.name == "THIRD_PARTY_NOTICES.md":
            notice_lines = [line.rstrip() for line in text.splitlines()]
            assert notice_lines[-3:] == [
                "Copyright (c) 2025",
                "Author: DarekDGB",
                "License: MIT",
            ]
            continue
        for line_number, line in enumerate(text.split("\n"), start=1):
            if _is_first_party_attribution_line(line):
                assert _is_allowed_first_party_attribution_line(line), (
                    f"unapproved first-party attribution in {path}:{line_number}"
                )


@pytest.mark.parametrize(
    "line",
    [
        "Author" + ": not-approved",
        "Owner" + ": not-approved",
        "Architect" + ": not-approved",
        "Assistant" + ": not-approved",
        "Copyright " + "(c) 2026 not-approved",
        "Implemented " + "by not-approved",
        "Implementation " + "by not-approved",
        "Maintained " + "by not-approved",
        "Prepared " + "by not-approved",
        "<!-- " + "Author: not-approved -->",
        "\u00a9 " + "not-approved",
    ],
)
def test_first_party_attribution_lock_rejects_unapproved_values(line: str) -> None:
    assert _is_first_party_attribution_line(line)
    assert not _is_allowed_first_party_attribution_line(line)


@pytest.mark.parametrize(
    "line",
    [
        "Author" + ": DarekDGB",
        "Owner" + ": DarekDGB",
        "Architect" + ": DarekDGB",
        "Assistant" + ": DarekDGB",
        "Copyright " + "(c) 2026 DarekDGB",
        "Implemented " + "by DarekDGB",
        "Implementation " + "by DarekDGB",
        "Maintained " + "by DarekDGB",
        "Prepared " + "by DarekDGB",
        "<!-- " + "Author: DarekDGB -->",
        "\u00a9 2026 " + "DarekDGB",
    ],
)
def test_first_party_attribution_lock_accepts_required_identity(line: str) -> None:
    assert _is_first_party_attribution_line(line)
    assert _is_allowed_first_party_attribution_line(line)
