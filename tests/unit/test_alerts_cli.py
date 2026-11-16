"""Unit tests for alerts and incidents CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from sentinellog.alerts.incidents import Incident
from sentinellog.alerts.store import AlertStore
from sentinellog.cli import app
from sentinellog.models import Alert, EvidenceRef, Severity

runner = CliRunner(env={"COLUMNS": "160"})


def _create_sample_alert() -> Alert:
    from datetime import UTC, datetime

    return Alert(
        rule_id="GEN-001",
        rule_name="Threat Intel Match",
        severity=Severity.HIGH,
        score=75,
        first_seen=datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC),
        last_seen=datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC),
        count=1,
        entities={"src_ip": ["198.51.100.4"]},
        evidence=[EvidenceRef(file="test.log", line_number=1, raw="log line")],
        mitre={"tactic": "Command and Control", "technique": "T1071"},
        explanation="Threat intel hit",
        recommended_action="Block IP",
    )


def test_cli_alerts_list_and_mark(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    store = AlertStore(db_file)
    alert = _create_sample_alert()
    alert_id = store.save_alert(alert)

    # 1. List alerts
    result_list = runner.invoke(app, ["alerts", "list", "--db", str(db_file)])
    assert result_list.exit_code == 0
    assert alert_id in result_list.stdout

    # 2. Mark alert
    result_mark = runner.invoke(
        app, ["alerts", "mark", alert_id, "--status", "acknowledged", "--db", str(db_file)]
    )
    assert result_mark.exit_code == 0
    assert "marked as acknowledged" in result_mark.stdout


def test_cli_incidents_list(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    db_file = tmp_path / "test.db"
    store = AlertStore(db_file)
    now = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)

    inc = Incident(
        id="INC-20261013-0001",
        title="Sample Incident",
        severity=Severity.HIGH,
        score=85,
        first_seen=now,
        last_seen=now,
        primary_entity="ip:198.51.100.4",
        alert_count=1,
    )
    store.save_incidents([inc])

    result = runner.invoke(app, ["incidents", "list", "--db", str(db_file)])
    assert result.exit_code == 0
    assert "INC-20261013-0001" in result.stdout
