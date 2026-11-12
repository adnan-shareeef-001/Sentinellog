"""Configurable JSON Lines log parser."""

import json
from datetime import UTC, datetime
from typing import Any

from sentinellog.models import Event, ensure_utc
from sentinellog.parsers.base import ParseContext, Parser

DEFAULT_FIELD_MAP = {
    "timestamp": "timestamp",
    "event_type": "event_type",
    "host": "host",
    "user": "user",
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "src_port": "src_port",
    "http_method": "http_method",
    "url": "url",
    "status_code": "status_code",
    "user_agent": "user_agent",
    "bytes_out": "bytes_out",
    "event_id": "event_id",
    "process": "process",
    "command_line": "command_line",
    "logon_type": "logon_type",
}


def _parse_ts(val: Any) -> datetime:
    """Parse timestamp value into UTC datetime."""
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(val, tz=UTC)
    s = str(val).strip().replace("Z", "+00:00")
    try:
        return ensure_utc(datetime.fromisoformat(s))
    except ValueError:
        return datetime.now(UTC)


class JSONLParser(Parser):
    """Parser for arbitrary JSON Lines with configurable field mappings."""

    def __init__(self, field_map: dict[str, str] | None = None) -> None:
        self.field_map = field_map or DEFAULT_FIELD_MAP

    @property
    def name(self) -> str:
        return "jsonl"

    def probe(self, line: str) -> bool:
        """Check if line is valid JSON."""
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                data = json.loads(stripped)
                return isinstance(data, dict)
            except Exception:
                return False
        return False

    def parse(
        self,
        line: str,
        file: str,
        line_number: int,
        ctx: ParseContext | None = None,
    ) -> Event | None:
        """Parse a JSON object line into a normalized Event."""
        stripped = line.strip()
        if not (stripped.startswith("{") and stripped.endswith("}")):
            if ctx:
                ctx.record_bad_line()
            return None

        try:
            data = json.loads(stripped)
        except Exception:
            if ctx:
                ctx.record_bad_line()
            return None

        if not isinstance(data, dict):
            if ctx:
                ctx.record_bad_line()
            return None

        ts_key = self.field_map.get("timestamp", "timestamp")
        raw_ts = data.get(ts_key) or datetime.now(UTC)
        timestamp = _parse_ts(raw_ts)

        et_key = self.field_map.get("event_type", "event_type")
        event_type = str(data.get(et_key) or "other")

        event = Event(
            timestamp=timestamp,
            source_type=self.name,
            host=str(data.get(self.field_map.get("host", "host")) or "") or None,
            event_type=event_type,
            user=str(data.get(self.field_map.get("user", "user")) or "") or None,
            src_ip=str(data.get(self.field_map.get("src_ip", "src_ip")) or "") or None,
            dst_ip=str(data.get(self.field_map.get("dst_ip", "dst_ip")) or "") or None,
            http_method=(
                str(data.get(self.field_map.get("http_method", "http_method")) or "") or None
            ),
            url=str(data.get(self.field_map.get("url", "url")) or "") or None,
            process=str(data.get(self.field_map.get("process", "process")) or "") or None,
            command_line=(
                str(data.get(self.field_map.get("command_line", "command_line")) or "") or None
            ),
            raw=line,
            file=file,
            line_number=line_number,
        )

        if ctx:
            ctx.record_event(event)
        return event
