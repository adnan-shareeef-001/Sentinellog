"""Pydantic models for SentinelLog normalized events, evidence, and alerts."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Alert severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceRef(BaseModel):
    """Reference to raw log line evidence."""

    model_config = ConfigDict(frozen=True)

    file: str
    line_number: int
    raw: str


class Event(BaseModel):
    """Normalized security log event schema."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    source_type: str  # ssh_auth | web_access | windows | syslog | jsonl
    host: str | None = None
    event_type: str  # auth_failure, auth_success, invalid_user, sudo_command, http_request, etc.
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    http_method: str | None = None
    url: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    bytes_out: int | None = None
    event_id: int | None = None
    process: str | None = None
    command_line: str | None = None
    logon_type: int | None = None
    raw: str
    file: str
    line_number: int


def generate_alert_id() -> str:
    """Generate a unique 12-character hex alert identifier."""
    return uuid4().hex[:12]


class Alert(BaseModel):
    """Security alert emitted by detection engines."""

    id: str = Field(default_factory=generate_alert_id)
    rule_id: str
    rule_name: str
    severity: Severity
    score: int
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    entities: dict[str, list[str]] = Field(default_factory=dict)  # src_ip, user, host
    evidence: list[EvidenceRef] = Field(default_factory=list)  # max 50
    mitre: dict[str, str] = Field(default_factory=dict)  # tactic, technique
    explanation: str = ""
    recommended_action: str = ""
    enrichment: dict[str, Any] = Field(default_factory=dict)
    status: str = "new"  # new | triaged | false_positive | resolved
    incident_id: str | None = None


def ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime object is timezone-aware and set to UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)
