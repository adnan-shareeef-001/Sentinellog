"""Base parser protocol, parsing context, and defensive utility functions."""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from sentinellog.models import Event

# Defensive limits
MAX_LINE_LENGTH = 8192
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi(value: str) -> str:
    """Remove ANSI escape sequences from input strings to prevent terminal injection."""
    return ANSI_ESCAPE_RE.sub("", value)


def truncate_line(line: str, max_len: int = MAX_LINE_LENGTH) -> tuple[str, bool]:
    """Truncate line if it exceeds max_len, returning the line and whether it was truncated."""
    if len(line) > max_len:
        return line[:max_len], True
    return line, False


@dataclass
class ParseContext:
    """Context and statistical accounting for a log ingestion session."""

    total_lines: int = 0
    parsed_events: int = 0
    bad_lines: int = 0
    truncated_lines: int = 0
    source_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    event_type_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def record_bad_line(self) -> None:
        """Increment count of unparseable or rejected lines."""
        self.bad_lines += 1

    def record_event(self, event: Event) -> None:
        """Record successful parsing of an event."""
        self.parsed_events += 1
        self.source_counts[event.source_type] += 1
        self.event_type_counts[event.event_type] += 1


@runtime_checkable
class Parser(Protocol):
    """Protocol defining the interface for log parsers."""

    @property
    def name(self) -> str:
        """Unique parser identifier."""
        ...

    def probe(self, line: str) -> bool:
        """Return True if this line matches the format signature with high confidence."""
        ...

    def parse(
        self,
        line: str,
        file: str,
        line_number: int,
        ctx: ParseContext | None = None,
    ) -> Event | None:
        """Parse a single raw line into a normalized Event.

        Must never raise exceptions; return None on unparseable lines.
        """
        ...
