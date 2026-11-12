"""Unit tests for the streaming log reader and file discovery."""

import gzip
from pathlib import Path

import pytest

from sentinellog.ingest.reader import discover_log_files, is_gzip_path, read_lines


def test_read_lines_plain(tmp_path: Path) -> None:
    """Verify reading plain text lines with accurate line numbers."""
    log_file = tmp_path / "test.log"
    log_file.write_text("line 1\nline 2\nline 3\n", encoding="utf-8")

    lines = list(read_lines(log_file))
    assert len(lines) == 3
    assert lines[0] == (1, "line 1")
    assert lines[1] == (2, "line 2")
    assert lines[2] == (3, "line 3")


def test_read_lines_gzipped(tmp_path: Path) -> None:
    """Verify streaming lines from gzip-compressed files."""
    gz_file = tmp_path / "test.log.gz"
    with gzip.open(gz_file, "wt", encoding="utf-8") as f:
        f.write("compressed line 1\ncompressed line 2\n")

    assert is_gzip_path(gz_file) is True
    lines = list(read_lines(gz_file))
    assert len(lines) == 2
    assert lines[0] == (1, "compressed line 1")
    assert lines[1] == (2, "compressed line 2")


def test_read_lines_oversized_truncation(tmp_path: Path) -> None:
    """Verify lines exceeding 8192 characters are truncated defensively."""
    log_file = tmp_path / "large.log"
    giant_line = "A" * 10000
    log_file.write_text(giant_line + "\n", encoding="utf-8")

    lines = list(read_lines(log_file, max_line_len=8192))
    assert len(lines) == 1
    assert len(lines[0][1]) == 8192


def test_read_lines_max_file_size_exceeded(tmp_path: Path) -> None:
    """Verify reading files exceeding max_file_bytes raises ValueError."""
    log_file = tmp_path / "huge.log"
    log_file.write_text("some content\n", encoding="utf-8")

    with pytest.raises(ValueError, match="exceeds limit"):
        list(read_lines(log_file, max_file_bytes=5))


def test_discover_log_files(tmp_path: Path) -> None:
    """Verify discovering log files recursively across supported extensions."""
    (tmp_path / "a.log").write_text("a", encoding="utf-8")
    (tmp_path / "b.jsonl").write_text("{}", encoding="utf-8")
    (tmp_path / "c.csv").write_text("1,2", encoding="utf-8")
    (tmp_path / "ignored.bin").write_text("bin", encoding="utf-8")

    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "nested.log.gz").write_bytes(b"\x1f\x8b\x08...")

    discovered = discover_log_files(tmp_path)
    names = [f.name for f in discovered]
    assert "a.log" in names
    assert "b.jsonl" in names
    assert "c.csv" in names
    assert "nested.log.gz" in names
    assert "ignored.bin" not in names
