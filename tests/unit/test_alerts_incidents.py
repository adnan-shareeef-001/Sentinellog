"""Unit tests for the incident correlation engine."""

from datetime import UTC, datetime, timedelta

from sentinellog.alerts.incidents import correlate_incidents
from sentinellog.models import Alert, EvidenceRef, Severity


def _sample_alert(
    rule_id: str,
    ts: datetime,
    host: str = "srv01",
    user: str = "admin",
    sev: Severity = Severity.HIGH,
) -> Alert:
    return Alert(
        rule_id=rule_id,
        rule_name=f"Rule {rule_id}",
        severity=sev,
        score=75 if sev == Severity.HIGH else 90,
        first_seen=ts,
        last_seen=ts,
        count=1,
        entities={"host": [host], "user": [user]},
        evidence=[EvidenceRef(file="app.log", line_number=1, raw="raw line")],
        mitre={"tactic": "Credential Access", "technique": "T1110"},
        explanation="Incident alert",
        recommended_action="Isolate host",
    )


def test_correlate_incidents_clustering() -> None:
    base_time = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)

    # 2 alerts targeting srv01 within 10 minutes
    a1 = _sample_alert("WIN-001", base_time, host="srv01", sev=Severity.HIGH)
    a2 = _sample_alert(
        "WIN-005", base_time + timedelta(minutes=10), host="srv01", sev=Severity.CRITICAL
    )

    incidents = correlate_incidents([a1, a2], window_seconds=1800)
    assert len(incidents) == 1

    inc = incidents[0]
    assert inc.alert_count == 2
    assert inc.severity == Severity.CRITICAL
    assert inc.primary_entity == "host:srv01"
    assert "WIN-001" in inc.title or "Multi-vector" in inc.title


def test_correlate_incidents_time_split() -> None:
    base_time = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)

    # 2 alerts targeting srv01, but 2 hours apart (exceeds 30m window)
    a1 = _sample_alert("WIN-001", base_time, host="srv01")
    a2 = _sample_alert("WIN-005", base_time + timedelta(hours=2), host="srv01")

    incidents = correlate_incidents([a1, a2], window_seconds=1800)
    assert len(incidents) == 2
