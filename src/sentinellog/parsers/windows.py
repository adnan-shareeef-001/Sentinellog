"""Windows Security Event Log parser supporting JSON Lines and CSV representations."""

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from sentinellog.models import Event, ensure_utc
from sentinellog.parsers.base import ParseContext, Parser

EVENT_ID_MAP = {
    4625: "auth_failure",
    4624: "auth_success",
    4688: "process_created",
    4698: "scheduled_task_created",
    4720: "user_created",
    4732: "group_member_added",
    1102: "log_cleared",
}


def _parse_windows_timestamp(ts_val: Any) -> datetime:
    """Parse Windows ISO-8601 or standard datetime formats."""
    if isinstance(ts_val, (int, float)):
        return datetime.fromtimestamp(ts_val, tz=UTC)
    ts_str = str(ts_val).strip()
    if not ts_str:
        return datetime.now(UTC)

    # Standard ISO format (e.g., 2026-10-13T10:15:30.123456Z)
    clean = ts_str.replace("Z", "+00:00")
    try:
        return ensure_utc(datetime.fromisoformat(clean))
    except ValueError:
        pass

    # Standard Windows CSV format: '10/13/2026 10:15:30 AM' or '2026-10-13 10:15:30'
    for fmt in (
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=UTC)
        except ValueError:
            continue

    return datetime.now(UTC)


def _clean_ip(ip_str: Any) -> str | None:
    """Normalize Windows IP addresses, treating '-', '::1', and empty strings as None."""
    if not ip_str:
        return None
    val = str(ip_str).strip()
    if val in ("-", "::1", "127.0.0.1", ""):
        return None
    return val


class WindowsParser(Parser):
    """Parser for Windows Security Event Logs exported as JSON Lines or CSV."""

    @property
    def name(self) -> str:
        return "windows"

    def probe(self, line: str) -> bool:
        """Check if line exhibits Windows Event structure (EventID, System, etc.)."""
        stripped = line.strip()
        if not stripped:
            return False

        # Check JSON Lines
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    if "EventID" in data or "event_id" in data:
                        return True
                    if "Event" in data and isinstance(data["Event"], dict):
                        return "System" in data["Event"]
            except Exception:  # noqa: S110
                pass

        # Check CSV header or data row containing EventID pattern
        if "4624" in stripped or "4625" in stripped or "4688" in stripped or "EventID" in stripped:
            return True

        return False

    def _parse_dict(
        self,
        data: dict[str, Any],
        raw_line: str,
        file: str,
        line_number: int,
        ctx: ParseContext | None = None,
    ) -> Event | None:
        """Extract event fields from normalized or nested dictionary."""
        # Handle nested Event.System / Event.EventData structure
        system_data: dict[str, Any] = {}
        event_data: dict[str, Any] = {}

        if "Event" in data and isinstance(data["Event"], dict):
            system_data = data["Event"].get("System", {})
            event_data = data["Event"].get("EventData", {})
        else:
            system_data = data
            event_data = data

        # Extract EventID
        raw_eid = (
            system_data.get("EventID")
            or system_data.get("event_id")
            or event_data.get("EventID")
            or data.get("EventID")
        )
        if isinstance(raw_eid, dict):
            raw_eid = raw_eid.get("#text") or raw_eid.get("Value")

        try:
            event_id = int(raw_eid) if raw_eid is not None else None
        except (ValueError, TypeError):
            event_id = None

        if event_id is None:
            if ctx:
                ctx.record_bad_line()
            return None

        # Extract Timestamp
        raw_ts = (
            system_data.get("TimeCreated")
            or system_data.get("TimeGenerated")
            or system_data.get("timestamp")
            or data.get("TimeCreated")
            or data.get("TimeGenerated")
        )
        if isinstance(raw_ts, dict):
            raw_ts = raw_ts.get("SystemTime")
        timestamp = _parse_windows_timestamp(raw_ts)

        # Extract Host / Computer
        raw_host = system_data.get("Computer") or data.get("Computer") or data.get("host") or ""
        host = str(raw_host) or None

        # Extract User
        user = (
            str(
                event_data.get("TargetUserName")
                or event_data.get("SubjectUserName")
                or data.get("TargetUserName")
                or data.get("user")
                or ""
            )
            or None
        )
        if user in ("-", ""):
            user = None

        # Extract Source IP
        src_ip = _clean_ip(
            event_data.get("IpAddress")
            or event_data.get("WorkstationName")
            or data.get("IpAddress")
            or data.get("src_ip")
        )

        # Extract LogonType
        raw_lt = event_data.get("LogonType") or data.get("LogonType") or data.get("logon_type")
        try:
            logon_type = int(raw_lt) if raw_lt is not None and str(raw_lt).isdigit() else None
        except (ValueError, TypeError):
            logon_type = None

        # Extract Process / CommandLine
        process = (
            str(
                event_data.get("NewProcessName")
                or event_data.get("Image")
                or data.get("NewProcessName")
                or data.get("process")
                or ""
            )
            or None
        )

        cmd_line = (
            str(
                event_data.get("CommandLine")
                or data.get("CommandLine")
                or data.get("command_line")
                or ""
            )
            or None
        )

        event_type = EVENT_ID_MAP.get(event_id, "other")

        event = Event(
            timestamp=timestamp,
            source_type=self.name,
            host=host,
            event_type=event_type,
            user=user,
            src_ip=src_ip,
            event_id=event_id,
            process=process,
            command_line=cmd_line,
            logon_type=logon_type,
            raw=raw_line,
            file=file,
            line_number=line_number,
        )

        if ctx:
            ctx.record_event(event)
        return event

    def parse(
        self,
        line: str,
        file: str,
        line_number: int,
        ctx: ParseContext | None = None,
    ) -> Event | None:
        """Parse a Windows Security log line (JSON Lines or CSV)."""
        stripped = line.strip()
        if not stripped:
            return None

        # Try JSON Lines
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    return self._parse_dict(data, line, file, line_number, ctx)
            except Exception:  # noqa: S110
                pass

        # Try CSV format
        try:
            reader = csv.reader(io.StringIO(stripped))
            row = next(reader, None)
            if row and len(row) >= 4:
                # Format: timestamp, event_id, host, user, src_ip, logon_type, process, cmdline
                # Basic positional fallback
                csv_data: dict[str, Any] = {}
                csv_data["TimeCreated"] = row[0]
                csv_data["EventID"] = row[1]
                csv_data["Computer"] = row[2]
                if len(row) > 3:
                    csv_data["TargetUserName"] = row[3]
                if len(row) > 4:
                    csv_data["IpAddress"] = row[4]
                if len(row) > 5:
                    csv_data["LogonType"] = row[5]
                if len(row) > 6:
                    csv_data["NewProcessName"] = row[6]
                if len(row) > 7:
                    csv_data["CommandLine"] = row[7]
                return self._parse_dict(csv_data, line, file, line_number, ctx)
        except Exception:  # noqa: S110
            pass

        if ctx:
            ctx.record_bad_line()
        return None
