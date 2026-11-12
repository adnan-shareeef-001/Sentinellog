"""Unit tests for SentinelLog Pydantic data models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sentinellog.models import Alert, Event, EvidenceRef, Severity, ensure_utc


def test_severity_values() -> None:
    """Verify all defined severity levels."""
    assert Severity.INFO.value == "info"
    assert Severity.LOW.value == "low"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.HIGH.value == "high"
    assert Severity.CRITICAL.value == "critical"


def test_ensure_utc() -> None:
    """Verify naive and aware datetimes are converted to UTC."""
    naive = datetime(2026, 10, 13, 10, 0, 0)
    aware = ensure_utc(naive)
    assert aware.tzinfo == UTC

    already_aware = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)
    assert ensure_utc(already_aware) == already_aware


def test_event_immutability() -> None:
    """Verify Event instances are frozen and immutable."""
    now = datetime.now(UTC)
    event = Event(
        timestamp=now,
        source_type="ssh_auth",
        event_type="auth_failure",
        raw="test raw line",
        file="auth.log",
        line_number=1,
    )
    assert event.source_type == "ssh_auth"
    assert event.event_type == "auth_failure"

    with pytest.raises(ValidationError):
        # Attempting to mutate a frozen model field raises ValidationError
        event.event_type = "auth_success"  # type: ignore[misc]


def test_alert_generation_and_defaults() -> None:
    """Verify Alert model default values, ID generation, and evidence refs."""
    now = datetime.now(UTC)
    alert = Alert(
        rule_id="SSH-001",
        rule_name="SSH Brute Force",
        severity=Severity.HIGH,
        score=75,
        first_seen=now,
        last_seen=now,
        entities={"src_ip": ["198.51.100.4"]},
        evidence=[EvidenceRef(file="auth.log", line_number=1, raw="failed password")],
    )
    assert len(alert.id) == 12
    assert alert.count == 1
    assert alert.status == "new"
    assert len(alert.evidence) == 1
    assert alert.evidence[0].file == "auth.log"
