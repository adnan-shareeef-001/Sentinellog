"""Generic Syslog parser supporting RFC3164 (BSD) and RFC5424 (IETF) formats."""

import re
from datetime import UTC, datetime

from sentinellog.models import Event, ensure_utc
from sentinellog.parsers.base import ParseContext, Parser

# RFC3164: <PRI>MMM DD HH:MM:SS HOST PROC[PID]: MSG
RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

# RFC5424: <PRI>VERSION TIMESTAMP HOST APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
RFC5424_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ver>\d+)\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)"
    r"(?:\s+(?P<sd>\[.*?\]|-))?"
    r"(?:\s+(?P<msg>.*))?$"
)


def _parse_syslog_ts(ts_str: str) -> datetime:
    """Parse syslog timestamp string into UTC datetime."""
    if "T" in ts_str:
        clean = ts_str.replace("Z", "+00:00")
        try:
            return ensure_utc(datetime.fromisoformat(clean))
        except ValueError:
            pass

    year = datetime.now(UTC).year
    normalized = re.sub(r"\s+", " ", ts_str.strip())
    try:
        dt = datetime.strptime(f"{year} {normalized}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=UTC)
    except ValueError:
        return datetime.now(UTC)


class SyslogParser(Parser):
    """Generic syslog parser handling RFC3164 and RFC5424 formatted messages."""

    @property
    def name(self) -> str:
        return "syslog"

    def probe(self, line: str) -> bool:
        """Check if line matches standard RFC3164 or RFC5424 signatures."""
        return bool(RFC3164_RE.match(line) or RFC5424_RE.match(line))

    def parse(
        self,
        line: str,
        file: str,
        line_number: int,
        ctx: ParseContext | None = None,
    ) -> Event | None:
        """Parse syslog line into normalized Event."""
        m5424 = RFC5424_RE.match(line)
        if m5424:
            ts = _parse_syslog_ts(m5424.group("ts"))
            host = m5424.group("host") if m5424.group("host") != "-" else None
            app_name = m5424.group("app") if m5424.group("app") != "-" else None

            event = Event(
                timestamp=ts,
                source_type=self.name,
                host=host,
                event_type="other",
                process=app_name,
                raw=line,
                file=file,
                line_number=line_number,
            )
            if ctx:
                ctx.record_event(event)
            return event

        m3164 = RFC3164_RE.match(line)
        if m3164:
            ts = _parse_syslog_ts(m3164.group("ts"))
            host = m3164.group("host")
            proc = m3164.group("proc")

            event = Event(
                timestamp=ts,
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

        if ctx:
            ctx.record_bad_line()
        return None
