"""Unit tests for the alert deduplication engine."""

from datetime import UTC, datetime, timedelta

from sentinellog.alerts.dedupe import AlertDeduplicator, deduplicate_alerts
from sentinellog.models import Alert, EvidenceRef, Severity


def _sample_alert(rule_id: str, ts: datetime, ip: str, count: int = 1) -> Alert:
    return Alert(
        rule_id=rule_id,
        rule_name="Test Rule",
        severity=Severity.HIGH,
        score=75,
        first_seen=ts,
        last_seen=ts,
        count=count,
        entities={"src_ip": [ip]},
        evidence=[EvidenceRef(file="test.log", line_number=1, raw=f"event at {ts}")],
        mitre={"tactic": "Initial Access", "technique": "T1078"},
        explanation="Test explanation",
        recommended_action="Block IP",
    )


def test_alert_deduplication_merging() -> None:
    deduper = AlertDeduplicator(window_seconds=300)
    base_time = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)

    # 3 duplicate alerts for same rule and IP within 2 minutes
    a1 = _sample_alert("SSH-001", base_time, "192.168.1.100", count=1)
    a2 = _sample_alert("SSH-001", base_time + timedelta(seconds=60), "192.168.1.100", count=2)
    a3 = _sample_alert("SSH-001", base_time + timedelta(seconds=120), "192.168.1.100", count=1)

    deduper.process_alert(a1)
    deduper.process_alert(a2)
    deduper.process_alert(a3)

    results = deduper.flush()
    assert len(results) == 1
    merged = results[0]
    assert merged.count == 4
    assert merged.first_seen == base_time
    assert merged.last_seen == base_time + timedelta(seconds=120)
    assert len(merged.evidence) == 3


def test_alert_deduplication_different_entities() -> None:
    base_time = datetime(2026, 10, 13, 10, 0, 0, tzinfo=UTC)
    a1 = _sample_alert("SSH-001", base_time, "10.0.0.1")
    a2 = _sample_alert("SSH-001", base_time, "10.0.0.2")

    deduped = deduplicate_alerts([a1, a2], window_seconds=300)
    assert len(deduped) == 2
