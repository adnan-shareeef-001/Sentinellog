"""Security validation tests: ANSI escapes, XSS, binary garbage, ReDoS, and malicious YAML."""

from pathlib import Path

import pytest

from sentinellog.ingest.reader import read_lines
from sentinellog.parsers.base import strip_ansi
from sentinellog.parsers.web_access import WebAccessParser
from sentinellog.rules.loader import load_rule
from sentinellog.rules.schema import validate_safe_regex


def test_ansi_escape_sanitization() -> None:
    """Verify ANSI escape codes are stripped from log lines."""
    malicious_ansi = "Normal text \x1b[31;1mRed Alert\x1b[0m more text"
    sanitized = strip_ansi(malicious_ansi)
    assert "\x1b" not in sanitized
    assert sanitized == "Normal text Red Alert more text"


def test_xss_script_in_url() -> None:
    """Verify <script> injection strings in URLs are safely parsed without execution."""
    parser = WebAccessParser()
    line = (
        "198.51.100.50 - - [13/Oct/2026:10:00:01 +0000] "
        '"GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 4523 "-" "Mozilla/5.0"'
    )
    event = parser.parse(line, "access.log", 1)
    assert event is not None
    assert "<script>alert(1)</script>" in event.url


def test_binary_garbage_line(tmp_path: Path) -> None:
    """Verify non-UTF8 binary garbage lines decode with errors='replace' without crashing."""
    binary_file = tmp_path / "corrupt.log"
    binary_file.write_bytes(b"Valid header\n\xff\xfe\x00\x01\x88Binary Garbage\nValid tail\n")

    lines = list(read_lines(binary_file))
    assert len(lines) == 3
    assert lines[0][1] == "Valid header"
    assert lines[2][1] == "Valid tail"


def test_oversized_one_megabyte_line(tmp_path: Path) -> None:
    """Verify 1 MB line is truncated to 8192 characters defensively."""
    huge_file = tmp_path / "huge_line.log"
    one_mb = "X" * (1024 * 1024)
    huge_file.write_text(one_mb + "\n", encoding="utf-8")

    lines = list(read_lines(huge_file))
    assert len(lines) == 1
    assert len(lines[0][1]) == 8192


def test_malicious_yaml_deserialization_rejected(tmp_path: Path) -> None:
    """Verify malicious YAML containing python object execution tags is rejected."""
    bad_yaml = tmp_path / "exploit.yaml"
    bad_yaml.write_text(
        "id: BAD-001\nname: !!python/object/apply:os.system ['echo hacked']\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_rule(bad_yaml)


def test_redos_nested_quantifiers_rejected() -> None:
    """Verify regexes with catastrophic backtracking nested quantifiers are rejected."""
    with pytest.raises(ValueError, match="Potentially catastrophic backtracking"):
        validate_safe_regex(r"(a+)+")

    with pytest.raises(ValueError, match="Potentially catastrophic backtracking"):
        validate_safe_regex(r"([0-9]+)*")
