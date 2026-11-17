"""SSH Authentication Log Parser supporting classic syslog and ISO timestamps."""

import os
import re
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from sentinellog.models import Event, ensure_utc
from sentinellog.parsers.base import ParseContext, Parser

# Classic: Oct 13 14:22:01 myhost sshd[1234]: ...
CLASSIC_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s"
    r"(?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s"
    r"(?P<msg>.*)$"
)

# ISO: 2026-10-13T14:22:01.123456+00:00 myhost sshd[1234]: ...
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s"
    r"(?P<host>\S+)\s"
    r"(?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s"
    r"(?P<msg>.*)$"
)

# SSHD Message Patterns
FAILED_PWD_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
ACCEPTED_PWD_RE = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
SUDO_RE = re.compile(r"(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$")


@lru_cache(maxsize=256)
def _get_file_year(file_path: str) -> int:
    """Cache file modification year to avoid repeated stat system calls."""
    try:
        p = Path(file_path)
        if p.is_file():
            mtime = os.path.getmtime(p)
            return datetime.fromtimestamp(mtime, tz=UTC).year
    except OSError:
        pass
    return datetime.now(UTC).year


MONTH_MAP = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _parse_timestamp(ts_str: str, file_path: str) -> datetime:
    """Parse classic or ISO timestamp, resolving year from file mtime if missing."""
    # Try ISO first
    if "T" in ts_str:
        clean_ts = ts_str.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(clean_ts)
            return ensure_utc(dt)
        except ValueError:
            pass

    # Classic syslog format (e.g., 'Oct 13 14:22:01' or 'Oct  3 04:12:00')
    inferred_year = _get_file_year(file_path)

    # Fast path for classic syslog timestamp
    parts = ts_str.split()
    if len(parts) == 3 and parts[0] in MONTH_MAP:
        try:
            m = MONTH_MAP[parts[0]]
            d = int(parts[1])
            time_parts = parts[2].split(":")
            if len(time_parts) == 3:
                h, minute, s = int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
                dt_utc = datetime(inferred_year, m, d, h, minute, s, tzinfo=UTC)
                now_utc = datetime.now(UTC)
                if dt_utc > now_utc:
                    dt_utc = dt_utc.replace(year=inferred_year - 1)
                return dt_utc
        except (ValueError, OverflowError):
            pass

    # Normalize multiple spaces in date (e.g. 'Oct  3')
    normalized_ts = re.sub(r"\s+", " ", ts_str.strip())
    try:
        dt = datetime.strptime(f"{inferred_year} {normalized_ts}", "%Y %b %d %H:%M:%S")
        dt_utc = dt.replace(tzinfo=UTC)
        # If timestamp is in the future relative to current time, subtract one year
        now_utc = datetime.now(UTC)
        if dt_utc > now_utc:
            dt_utc = dt_utc.replace(year=inferred_year - 1)
        return dt_utc
    except ValueError:
        return datetime.now(UTC)


class SSHAuthParser(Parser):
    """Parser for SSH and sudo authentication log events."""

    @property
    def name(self) -> str:
        return "ssh_auth"

    def probe(self, line: str) -> bool:
        """Return True if line matches SSH or sudo log structure."""
        m = ISO_RE.match(line) or CLASSIC_RE.match(line)
        if not m:
            return False
        proc = m.group("proc")
        return proc.startswith("sshd") or proc == "sudo"

    def parse(
        self,
        line: str,
        file: str,
        line_number: int,
        ctx: ParseContext | None = None,
    ) -> Event | None:
        """Parse SSH authentication log line into normalized Event."""
        m = ISO_RE.match(line) or CLASSIC_RE.match(line)
        if not m:
            if ctx:
                ctx.record_bad_line()
            return None

        ts_str = m.group("ts")
        host = m.group("host")
        proc = m.group("proc")
        msg = m.group("msg")

        timestamp = _parse_timestamp(ts_str, file)

        # Check for sudo lines
        if proc == "sudo" or "COMMAND=" in msg:
            sudo_match = SUDO_RE.search(msg)
            if sudo_match:
                event = Event(
                    timestamp=timestamp,
                    source_type=self.name,
                    host=host,
                    event_type="sudo_command",
                    user=sudo_match.group("user"),
                    process="sudo",
                    command_line=sudo_match.group("cmd").strip(),
                    raw=line,
                    file=file,
                    line_number=line_number,
                )
                if ctx:
                    ctx.record_event(event)
                return event

        # Process SSHD lines
        if proc.startswith("sshd"):
            # 1. Failed password
            fail_m = FAILED_PWD_RE.search(msg)
            if fail_m:
                event = Event(
                    timestamp=timestamp,
                    source_type=self.name,
                    host=host,
                    event_type="auth_failure",
                    user=fail_m.group("user"),
                    src_ip=fail_m.group("ip"),
                    src_port=int(fail_m.group("port")),
                    process=proc,
                    raw=line,
                    file=file,
                    line_number=line_number,
                )
                if ctx:
                    ctx.record_event(event)
                return event

            # 2. Accepted password / publickey
            acc_m = ACCEPTED_PWD_RE.search(msg)
            if acc_m:
                event = Event(
                    timestamp=timestamp,
                    source_type=self.name,
                    host=host,
                    event_type="auth_success",
                    user=acc_m.group("user"),
                    src_ip=acc_m.group("ip"),
                    src_port=int(acc_m.group("port")),
                    process=proc,
                    raw=line,
                    file=file,
                    line_number=line_number,
                )
                if ctx:
                    ctx.record_event(event)
                return event

            # 3. Invalid user
            inv_m = INVALID_USER_RE.search(msg)
            if inv_m:
                user_val = inv_m.group("user")
                port_str = inv_m.group("port")
                event = Event(
                    timestamp=timestamp,
                    source_type=self.name,
                    host=host,
                    event_type="invalid_user",
                    user=user_val if user_val else None,
                    src_ip=inv_m.group("ip"),
                    src_port=int(port_str) if port_str else None,
                    process=proc,
                    raw=line,
                    file=file,
                    line_number=line_number,
                )
                if ctx:
                    ctx.record_event(event)
                return event

            # Valid sshd line but other message
            event = Event(
                timestamp=timestamp,
                source_type=self.name,
                host=host,
                event_type="other",
                process=proc,
                raw=line,
                file=file,
                line_number=line_number,
            )
            if ctx:
                ctx.record_event(event)
            return event

        # Did not match recognized ssh/sudo pattern
        if ctx:
            ctx.record_bad_line()
        return None
