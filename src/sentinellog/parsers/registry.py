"""Parser registry and auto-detection dispatcher."""

from collections.abc import Sequence
from pathlib import Path

from sentinellog.ingest.reader import read_lines
from sentinellog.parsers.base import Parser
from sentinellog.parsers.jsonl import JSONLParser
from sentinellog.parsers.ssh_auth import SSHAuthParser
from sentinellog.parsers.syslog import SyslogParser
from sentinellog.parsers.web_access import WebAccessParser
from sentinellog.parsers.windows import WindowsParser

# Global parser registry
_PARSER_REGISTRY: dict[str, Parser] = {}
_PARSER_ALIASES: dict[str, str] = {
    "ssh": "ssh_auth",
    "web": "web_access",
    "win": "windows",
    "syslog": "syslog",
    "json": "jsonl",
}


def register_parser(parser: Parser) -> None:
    """Register a parser instance in the global registry."""
    _PARSER_REGISTRY[parser.name] = parser


def get_parser(name: str) -> Parser:
    """Retrieve a registered parser by its canonical name or alias."""
    canonical = _PARSER_ALIASES.get(name.lower(), name.lower())
    if canonical not in _PARSER_REGISTRY:
        available = list(_PARSER_REGISTRY.keys()) + list(_PARSER_ALIASES.keys())
        msg = f"Unknown parser format '{name}'. Registered formats: {', '.join(sorted(available))}"
        raise KeyError(msg)
    return _PARSER_REGISTRY[canonical]


def detect_format(sample_lines: Sequence[str]) -> str:
    """Probe up to 20 non-empty lines and return the best matching parser format.

    Requires at least a 60% match rate across the sampled lines.
    Falls back to 'syslog' if no parser meets the threshold.
    """
    non_empty = [ln.strip() for ln in sample_lines if ln.strip()][:20]
    if not non_empty:
        return "syslog"

    total = len(non_empty)
    best_format = "syslog"
    best_rate = 0.0

    # Probe order: check specific parsers before generic syslog
    probe_order = ["windows", "ssh_auth", "web_access", "jsonl", "syslog"]
    for parser_name in probe_order:
        parser = _PARSER_REGISTRY.get(parser_name)
        if not parser:
            continue
        matches = sum(1 for line in non_empty if parser.probe(line))
        rate = matches / total
        if rate > best_rate:
            best_rate = rate
            best_format = parser_name

    # Require >= 60% match rate
    if best_rate >= 0.60:
        return best_format

    return "syslog"


def detect_file_format(file_path: Path | str) -> str:
    """Detect parser format for a given log file by inspecting its initial lines."""
    p = Path(file_path)
    # Fast path by extension
    if p.suffix.lower() == ".jsonl":
        # Check first line for Windows vs general JSONL
        try:
            for _, line in read_lines(file_path):
                if line.strip():
                    if WindowsParser().probe(line):
                        return "windows"
                    return "jsonl"
        except Exception:  # noqa: S110
            pass

    sample_lines: list[str] = []
    try:
        for _, line in read_lines(file_path):
            if line.strip():
                sample_lines.append(line)
            if len(sample_lines) >= 20:
                break
    except Exception:
        return "syslog"

    return detect_format(sample_lines)


# Initialize default parsers
register_parser(WindowsParser())
register_parser(SSHAuthParser())
register_parser(WebAccessParser())
register_parser(JSONLParser())
register_parser(SyslogParser())
