"""Unit tests for SQLite persistent storage of alerts and incidents."""

from datetime import UTC, datetime
from pathlib import Path

from sentinellog.alerts.incidents import Incident
from sentinellog.alerts.store import AlertStore
from sentinellog.models import Alert, EvidenceRef, Severity


def _create_sample_alert() -> Alert:
    return Alert(
        rule_id="SSH-001",
        rule_name="SSH Brute Force",
        severity=Severity.HIGH,
        score=75,
        first_seen=datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC),
        last_seen=datetime(2026, 10, 13, 10, 5, 0, tzinfo=UTC),
        count=10,
        entities={"src_ip": ["198.51.100.4"]},
        evidence=[EvidenceRef(file="auth.log", line_number=5, raw="sample failed login")],
        mitre={"tactic": "Credential Access", "technique": "T1110.001"},
        explanation="Test explanation",
        recommended_action="Block IP",
    )


def test_alert_store_crud(tmp_path: Path) -> None:
    db_file = tmp_path / "test_alerts.db"
    store = AlertStore(db_file)

    alert = _create_sample_alert()
    alert_id = store.save_alert(alert)
    assert alert_id.startswith("ALT-")

    # Retrieve alerts
    alerts = store.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SSH-001"
    assert alerts[0]["status"] == "new"

    # Single alert fetch
    fetched = store.get_alert(alert_id)
    assert fetched is not None
    assert fetched["id"] == alert_id

    # Update status
    updated = store.update_alert_status(alert_id, "acknowledged")
    assert updated is True

    ack_alerts = store.get_alerts(status="acknowledged")
    assert len(ack_alerts) == 1
    assert ack_alerts[0]["id"] == alert_id


def test_alert_store_incidents(tmp_path: Path) -> None:
    db_file = tmp_path / "test_incidents.db"
    store = AlertStore(db_file)

    alert = _create_sample_alert()
    now = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)
    incident = Incident(
        id="INC-20261013-0001",
        title="Test Incident",
        severity=Severity.HIGH,
        score=80,
        first_seen=now,
        last_seen=now,
        primary_entity="ip:198.51.100.4",
        alert_count=1,
        alerts=[alert],
        entities={"src_ip": ["198.51.100.4"]},
    )

    saved_ids = store.save_incidents([incident])
    assert "INC-20261013-0001" in saved_ids

    incidents = store.get_incidents()
    assert len(incidents) == 1
    assert incidents[0]["id"] == "INC-20261013-0001"

    # Update incident status
    store.update_incident_status("INC-20261013-0001", "resolved")
    resolved = store.get_incidents(status="resolved")
    assert len(resolved) == 1
