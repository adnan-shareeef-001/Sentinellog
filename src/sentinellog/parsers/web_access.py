"""Apache and Nginx Combined web access log parser."""

import re
import urllib.parse
from datetime import UTC, datetime

from sentinellog.models import Event, ensure_utc
from sentinellog.parsers.base import ParseContext, Parser

# Apache/Nginx Combined Log Pattern
COMBINED_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/[\d.]+)?'
    r'"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def _parse_web_timestamp(ts_str: str) -> datetime:
    """Parse web server timestamp format: 10/Oct/2026:13:55:36 +0000."""
    try:
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return ensure_utc(dt)
    except ValueError:
        # Fallback if timezone offset is missing
        try:
            clean_ts = ts_str.split()[0]
            dt = datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
            return dt.replace(tzinfo=UTC)
        except ValueError:
            return datetime.now(UTC)


class WebAccessParser(Parser):
    """Parser for Apache and Nginx Combined web server access logs."""

    @property
    def name(self) -> str:
        return "web_access"

    def probe(self, line: str) -> bool:
        """Return True if line matches Apache/Nginx Combined log format."""
        return COMBINED_RE.match(line) is not None

    def parse(
        self,
        line: str,
        file: str,
        line_number: int,
        ctx: ParseContext | None = None,
    ) -> Event | None:
        """Parse web access log line into normalized Event."""
        m = COMBINED_RE.match(line)
        if not m:
            if ctx:
                ctx.record_bad_line()
            return None

        ip = m.group("ip")
        user_val = m.group("user")
        ts_str = m.group("ts")
        method = m.group("method")
        raw_url = m.group("url")
        status_str = m.group("status")
        bytes_str = m.group("bytes")
        ua_str = m.group("ua")

        timestamp = _parse_web_timestamp(ts_str)

        # Percent-decode URL safely
        try:
            decoded_url = urllib.parse.unquote(raw_url)
        except Exception:
            decoded_url = raw_url

        user = None if user_val == "-" else user_val
        status_code = int(status_str) if status_str.isdigit() else None
        bytes_out = int(bytes_str) if bytes_str.isdigit() else None
        user_agent = None if ua_str in (None, "-") else ua_str

        event = Event(
            timestamp=timestamp,
            source_type=self.name,
            event_type="http_request",
            src_ip=ip,
            user=user,
            http_method=method,
            url=decoded_url,
            status_code=status_code,
            bytes_out=bytes_out,
            user_agent=user_agent,
            raw=line,
            file=file,
            line_number=line_number,
        )

        if ctx:
            ctx.record_event(event)
        return event
