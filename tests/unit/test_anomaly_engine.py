"""Unit tests for the anomaly detection engine (off-hours & rate-spikes)."""

from datetime import UTC, datetime, timedelta

from sentinellog.engine.anomaly import AnomalyEngine
from sentinellog.models import Event, Severity
from sentinellog.rules.schema import (
    DetectionConfig,
    MitreMapping,
    ResponseConfig,
    Rule,
    RuleTestsConfig,
)


def _make_offhours_rule() -> Rule:
    return Rule(
        id="ANOM-001",
        name="Offhours Login",
        description="Offhours activity",
        severity=Severity.MEDIUM,
        type="anomaly",
        log_source="any",
        mitre=MitreMapping(tactic="Initial Access", technique="T1078"),
        detection=DetectionConfig(
            kind="offhours",
            filter={"event_type": "auth_success"},
            hours={
                "start": "08:00",
                "end": "18:00",
                "days": ["mon", "tue", "wed", "thu", "fri"],
            },
        ),
        exceptions={"user__in": ["backup_service"]},
        response=ResponseConfig(recommended_action="Investigate"),
        tests=RuleTestsConfig(should_fire="none.log", should_not_fire="none.log"),
    )


def _make_rate_spike_rule() -> Rule:
    return Rule(
        id="ANOM-002",
        name="Rate Spike",
        description="Rate spike activity",
        severity=Severity.HIGH,
        type="anomaly",
        log_source="any",
        mitre=MitreMapping(tactic="Impact", technique="T1499"),
        detection=DetectionConfig(
            kind="rate_spike",
            filter={"status_code__gte": 500},
            threshold=3,
            window="5m",
            z=2.0,
        ),
        response=ResponseConfig(recommended_action="Inspect backend"),
        tests=RuleTestsConfig(should_fire="none.log", should_not_fire="none.log"),
    )


def test_anomaly_offhours_trigger() -> None:
    engine = AnomalyEngine()
    rule = _make_offhours_rule()

    # Sunday at 02:00 UTC (Off-hours!)
    sunday_ts = datetime(2026, 10, 18, 2, 0, 0, tzinfo=UTC)
    evt_off = Event(
        timestamp=sunday_ts,
        source_type="ssh_auth",
        event_type="auth_success",
        user="alice",
        src_ip="10.0.0.1",
        raw="login",
        file="auth.log",
        line_number=1,
    )
    alert = engine.evaluate(rule, evt_off)
    assert alert is not None
    assert alert.rule_id == "ANOM-001"
    assert "off-hours activity detected" in alert.explanation


def test_anomaly_business_hours_suppression() -> None:
    engine = AnomalyEngine()
    rule = _make_offhours_rule()

    # Wednesday at 10:00 UTC (Business hours!)
    wed_ts = datetime(2026, 10, 14, 10, 0, 0, tzinfo=UTC)
    evt_on = Event(
        timestamp=wed_ts,
        source_type="ssh_auth",
        event_type="auth_success",
        user="alice",
        src_ip="10.0.0.1",
        raw="login",
        file="auth.log",
        line_number=2,
    )
    alert = engine.evaluate(rule, evt_on)
    assert alert is None


def test_anomaly_offhours_exception() -> None:
    engine = AnomalyEngine()
    rule = _make_offhours_rule()

    # Sunday at 02:00 UTC, but user is backup_service
    sunday_ts = datetime(2026, 10, 18, 2, 0, 0, tzinfo=UTC)
    evt_exc = Event(
        timestamp=sunday_ts,
        source_type="ssh_auth",
        event_type="auth_success",
        user="backup_service",
        src_ip="10.0.0.1",
        raw="login",
        file="auth.log",
        line_number=3,
    )
    alert = engine.evaluate(rule, evt_exc)
    assert alert is None


def test_anomaly_rate_spike() -> None:
    engine = AnomalyEngine()
    rule = _make_rate_spike_rule()
    base_ts = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)

    alerts = []
    # Emit 4 500 errors in 30 seconds (threshold is 3)
    for i in range(4):
        evt = Event(
            timestamp=base_ts + timedelta(seconds=i * 5),
            source_type="web_access",
            event_type="http_request",
            status_code=500,
            src_ip="10.0.0.1",
            raw=f"500 err {i}",
            file="access.log",
            line_number=i + 1,
        )
        res = engine.evaluate(rule, evt)
        if res:
            alerts.append(res)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "ANOM-002"
    assert alerts[0].count == 3
