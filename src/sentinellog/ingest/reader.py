"""Streaming log reader supporting plain text, gzip archives, and directory traversal."""

import gzip
from collections.abc import Iterator
from pathlib import Path

from sentinellog.parsers.base import MAX_LINE_LENGTH, strip_ansi, truncate_line

DEFAULT_MAX_FILE_BYTES = 500 * 1024 * 1024  # 500 MB
SUPPORTED_EXTENSIONS = {".log", ".gz", ".json", ".jsonl", ".csv", ".txt"}


def is_gzip_path(path: Path) -> bool:
    """Check if file is a gzip file by extension or signature."""
    if path.suffix.lower() == ".gz":
        return True
    try:
        with open(path, "rb") as f:
            magic = f.read(2)
            return magic == b"\x1f\x8b"
    except OSError:
        return False


def discover_log_files(target: Path | str) -> list[Path]:
    """Find all supported log files within a file path or directory recursively."""
    target_path = Path(target)
    if not target_path.exists():
        return []

    if target_path.is_file():
        return [target_path]

    discovered: list[Path] = []
    ignored_names = {"labels.json", "report.json", "package.json", "alerts.json"}
    for item in target_path.rglob("*"):
        if item.is_file() and not item.name.startswith("."):
            if item.name.lower() in ignored_names:
                continue
            if item.suffix.lower() in SUPPORTED_EXTENSIONS:
                discovered.append(item)

    discovered.sort()
    return discovered


def read_lines(
    path: Path | str,
    max_line_len: int = MAX_LINE_LENGTH,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> Iterator[tuple[int, str]]:
    """Stream lines from a plain or gzipped log file line by line.

    Yields (line_number, line_content) with 1-based indexing.
    Never loads the entire file into memory. Truncates oversized lines safely.
    """
    file_path = Path(path)
    if not file_path.is_file():
        return

    file_size = file_path.stat().st_size
    if file_size > max_file_bytes:
        msg = f"File {file_path} size ({file_size} bytes) exceeds limit ({max_file_bytes} bytes)"
        raise ValueError(msg)

    line_number = 0
    if is_gzip_path(file_path):
        open_fn = gzip.open(file_path, "rt", encoding="utf-8", errors="replace")
    else:
        open_fn = open(file_path, encoding="utf-8", errors="replace")

    with open_fn as handle:
        for raw_line in handle:
            line_number += 1
            line = raw_line.rstrip("\r\n")
            # Truncate defensively if line exceeds safe threshold
            truncated, _ = truncate_line(line, max_len=max_line_len)
            sanitized = strip_ansi(truncated)
            yield line_number, sanitized
