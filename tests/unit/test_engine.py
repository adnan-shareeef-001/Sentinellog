"""Unit tests for the detection engines and filter operators."""

from datetime import UTC, datetime, timedelta

from sentinellog.engine.engine import DetectionEngine
from sentinellog.engine.match import (
    matches_allowlist,
    matches_exceptions,
    matches_filter,
)
from sentinellog.engine.threshold import ThresholdEngine
from sentinellog.models import Event, Severity
from sentinellog.rules.schema import DetectionConfig, MitreMapping, Rule, RuleTestsConfig


def _make_event(
    ts: datetime | None = None,
    src_ip: str = "198.51.100.4",
    user: str = "alice",
    event_type: str = "auth_failure",
    status_code: int = 404,
    url: str = "/login",
    user_agent: str = "curl/7.88",
    command_line: str = "/bin/bash",
) -> Event:
    return Event(
        timestamp=ts or datetime.now(UTC),
        source_type="ssh_auth",
        event_type=event_type,
        src_ip=src_ip,
        user=user,
        status_code=status_code,
        url=url,
        user_agent=user_agent,
        command_line=command_line,
        raw="raw log text",
        file="auth.log",
        line_number=1,
    )


def test_filter_operators() -> None:
    """Verify all filter operators: exact, in, contains, icontains, regex, cidr, etc."""
    event = _make_event(src_ip="198.51.100.4", status_code=500, url="/search?q=test")

    # exact
    assert matches_filter(event, {"event_type": "auth_failure"}) is True
    assert matches_filter(event, {"event_type": "auth_success"}) is False

    # __in
    assert matches_filter(event, {"status_code__in": [200, 500, 404]}) is True
    assert matches_filter(event, {"status_code__in": [200, 301]}) is False

    # __contains and __icontains
    assert matches_filter(event, {"url__contains": "search"}) is True
    assert matches_filter(event, {"url__contains": "SEARCH"}) is False
    assert matches_filter(event, {"url__icontains": "SEARCH"}) is True

    # __regex
    assert matches_filter(event, {"src_ip__regex": r"^198\.51\.\d+\.\d+$"}) is True
    assert matches_filter(event, {"src_ip__regex": r"^10\."}) is False

    # __cidr
    assert matches_filter(event, {"src_ip__cidr": "198.51.100.0/24"}) is True
    assert matches_filter(event, {"src_ip__cidr": "10.0.0.0/8"}) is False

    # __gte and __lte
    assert matches_filter(event, {"status_code__gte": 400}) is True
    assert matches_filter(event, {"status_code__gte": 600}) is False
    assert matches_filter(event, {"status_code__lte": 500}) is True
    assert matches_filter(event, {"status_code__lte": 400}) is False

    # __exists
    assert matches_filter(event, {"user__exists": True}) is True
    assert matches_filter(event, {"dst_ip__exists": True}) is False


def test_exceptions_and_allowlist() -> None:
    """Verify rule exceptions and global allowlists suppress events."""
    event = _make_event(src_ip="10.0.0.5", user="backup_service")

    # Exceptions
    assert matches_exceptions(event, {"src_ip_in": ["10.0.0.5"]}) is True
    assert matches_exceptions(event, {"src_ip_in": ["192.168.1.1"]}) is False

    # Allowlist
    allowlist = {
        "trusted_ips": [{"ip": "10.0.0.5"}],
        "service_accounts": [{"user": "backup_service"}],
    }
    assert matches_allowlist(event, allowlist) is True
    assert matches_allowlist(_make_event(src_ip="198.51.100.4", user="mallory"), allowlist) is False


def test_threshold_engine_boundary_and_cooldown() -> None:
    """Verify threshold boundary: one below, exact, window eviction, and cooldown."""
    rule = Rule(
        id="SSH-001",
        name="SSH Brute Force",
        description="SSH brute force",
        severity=Severity.HIGH,
        type="threshold",
        log_source="ssh_auth",
        mitre=MitreMapping(tactic="Credential Access", technique="T1110.001"),
        detection=DetectionConfig(
            filter={"event_type": "auth_failure"},
            group_by=["src_ip"],
            threshold=3,
            window="1m",
        ),
        tests=RuleTestsConfig(should_fire="a", should_not_fire="b"),
    )

    engine = ThresholdEngine()
    now = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)

    # Event 1: count = 1 (< 3)
    a1 = engine.evaluate(rule, _make_event(ts=now))
    assert a1 is None

    # Event 2: count = 2 (< 3) - boundary: one below threshold
    a2 = engine.evaluate(rule, _make_event(ts=now + timedelta(seconds=10)))
    assert a2 is None

    # Event 3: count = 3 (== 3) - exactly at threshold -> fires!
    a3 = engine.evaluate(rule, _make_event(ts=now + timedelta(seconds=20)))
    assert a3 is not None
    assert a3.rule_id == "SSH-001"
    assert a3.count == 3

    # Event 4: within cooldown window (1m) -> suppressed duplicate alert
    a4 = engine.evaluate(rule, _make_event(ts=now + timedelta(seconds=30)))
    assert a4 is None

    # Event 5: after cooldown window (> 1m elapsed)
    a5 = engine.evaluate(rule, _make_event(ts=now + timedelta(seconds=100)))
    assert a5 is None  # only 1 event inside new window


def test_threshold_engine_distinct_counting() -> None:
    """Verify threshold engine with distinct field option."""
    rule = Rule(
        id="SSH-002",
        name="SSH Password Spraying",
        description="Spraying test",
        severity=Severity.HIGH,
        type="threshold",
        log_source="ssh_auth",
        mitre=MitreMapping(tactic="Credential Access", technique="T1110.003"),
        detection=DetectionConfig(
            filter={"event_type": "auth_failure"},
            group_by=["src_ip"],
            threshold=3,
            window="5m",
            distinct="user",
        ),
        tests=RuleTestsConfig(should_fire="a", should_not_fire="b"),
    )

    engine = ThresholdEngine()
    now = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)

    # 3 failures for SAME user -> distinct count = 1 -> should NOT fire
    engine.evaluate(rule, _make_event(ts=now, user="userA"))
    engine.evaluate(rule, _make_event(ts=now + timedelta(seconds=5), user="userA"))
    alert_same = engine.evaluate(rule, _make_event(ts=now + timedelta(seconds=10), user="userA"))
    assert alert_same is None

    # Now add userB and userC -> distinct count = 3 -> FIRES!
    engine.evaluate(rule, _make_event(ts=now + timedelta(seconds=15), user="userB"))
    alert_distinct = engine.evaluate(
        rule, _make_event(ts=now + timedelta(seconds=20), user="userC")
    )
    assert alert_distinct is not None
    assert alert_distinct.rule_id == "SSH-002"


def test_detection_engine_reorder_buffer() -> None:
    """Verify reorder buffer sorts slightly out-of-order events by timestamp."""
    rule = Rule(
        id="SSH-004",
        name="Direct Root Login",
        description="Root attempt",
        severity=Severity.HIGH,
        type="match",
        log_source="ssh_auth",
        mitre=MitreMapping(tactic="Initial Access", technique="T1078.001"),
        detection=DetectionConfig(filter={"user": "root"}),
        tests=RuleTestsConfig(should_fire="a", should_not_fire="b"),
    )

    engine = DetectionEngine(rules=[rule])
    now = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)

    # Feed events slightly out of order
    e2 = _make_event(ts=now + timedelta(seconds=10), user="root")
    e1 = _make_event(ts=now, user="alice")

    engine.process_event(e2)
    engine.process_event(e1)
    alerts = engine.flush()

    assert len(alerts) == 1
    assert alerts[0].rule_id == "SSH-004"
