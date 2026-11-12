"""Unit tests for the multi-stage sequence correlation engine."""

from datetime import UTC, datetime, timedelta

from sentinellog.engine.sequence import SequenceEngine
from sentinellog.models import Event, Severity
from sentinellog.rules.schema import (
    DetectionConfig,
    MitreMapping,
    ResponseConfig,
    Rule,
    RuleTestsConfig,
    StepConfig,
)


def _create_test_sequence_rule() -> Rule:
    return Rule(
        id="SEQ-001",
        name="Test Auth Failure Then Success",
        description="Detects failures followed by success",
        severity=Severity.HIGH,
        type="sequence",
        log_source="any",
        mitre=MitreMapping(tactic="Initial Access", technique="T1078"),
        detection=DetectionConfig(
            steps=[
                StepConfig(filter={"event_type": "auth_failure"}, min_count=3),
                StepConfig(filter={"event_type": "auth_success"}, min_count=1),
            ],
            same=["src_ip"],
            window="5m",
        ),
        response=ResponseConfig(recommended_action="Block IP"),
        tests=RuleTestsConfig(
            should_fire="tests/fixtures/ssh_brute_then_success.log",
            should_not_fire="tests/fixtures/ssh_normal.log",
        ),
    )


def test_sequence_engine_successful_correlation() -> None:
    engine = SequenceEngine()
    rule = _create_test_sequence_rule()
    base_ts = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)

    # 3 failures from 10.0.0.1
    for i in range(3):
        evt = Event(
            timestamp=base_ts + timedelta(seconds=i * 10),
            source_type="ssh_auth",
            event_type="auth_failure",
            src_ip="10.0.0.1",
            raw=f"fail {i}",
            file="auth.log",
            line_number=i + 1,
        )
        alert = engine.evaluate(rule, evt)
        assert alert is None

    # 1 success from 10.0.0.1
    succ_evt = Event(
        timestamp=base_ts + timedelta(seconds=60),
        source_type="ssh_auth",
        event_type="auth_success",
        src_ip="10.0.0.1",
        raw="success",
        file="auth.log",
        line_number=4,
    )
    alert = engine.evaluate(rule, succ_evt)
    assert alert is not None
    assert alert.rule_id == "SEQ-001"
    assert alert.count == 4
    assert alert.entities["src_ip"] == ["10.0.0.1"]


def test_sequence_engine_different_ip_no_correlation() -> None:
    engine = SequenceEngine()
    rule = _create_test_sequence_rule()
    base_ts = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)

    # 3 failures from 10.0.0.1
    for i in range(3):
        evt = Event(
            timestamp=base_ts + timedelta(seconds=i * 10),
            source_type="ssh_auth",
            event_type="auth_failure",
            src_ip="10.0.0.1",
            raw=f"fail {i}",
            file="auth.log",
            line_number=i + 1,
        )
        engine.evaluate(rule, evt)

    # Success from 10.0.0.2 (different IP)
    succ_evt = Event(
        timestamp=base_ts + timedelta(seconds=60),
        source_type="ssh_auth",
        event_type="auth_success",
        src_ip="10.0.0.2",
        raw="success",
        file="auth.log",
        line_number=4,
    )
    alert = engine.evaluate(rule, succ_evt)
    assert alert is None


def test_sequence_engine_window_expiration() -> None:
    engine = SequenceEngine()
    rule = _create_test_sequence_rule()
    base_ts = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)

    # 3 failures from 10.0.0.1
    for i in range(3):
        evt = Event(
            timestamp=base_ts + timedelta(seconds=i * 10),
            source_type="ssh_auth",
            event_type="auth_failure",
            src_ip="10.0.0.1",
            raw=f"fail {i}",
            file="auth.log",
            line_number=i + 1,
        )
        engine.evaluate(rule, evt)

    # Success after 10 minutes (exceeds 5m window)
    succ_evt = Event(
        timestamp=base_ts + timedelta(minutes=10),
        source_type="ssh_auth",
        event_type="auth_success",
        src_ip="10.0.0.1",
        raw="success",
        file="auth.log",
        line_number=4,
    )
    alert = engine.evaluate(rule, succ_evt)
    assert alert is None
