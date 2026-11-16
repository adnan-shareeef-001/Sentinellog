"""Unit tests for the risk score calculation engine."""

from sentinellog.alerts.scoring import calculate_risk_score, score_to_severity
from sentinellog.models import Severity


def test_calculate_risk_score_base() -> None:
    assert calculate_risk_score(Severity.LOW) == 25
    assert calculate_risk_score(Severity.MEDIUM) == 50
    assert calculate_risk_score(Severity.HIGH) == 75
    assert calculate_risk_score(Severity.CRITICAL) == 90


def test_calculate_risk_score_modifiers() -> None:
    # High base (75) + critical asset (+15) + threat intel (+20) = 110 -> clamped to 100
    score = calculate_risk_score(
        Severity.HIGH,
        asset_criticality="critical",
        is_threat_intel_match=True,
    )
    assert score == 100

    # Low base (25) + medium asset (+5) + high count (+10) = 40
    score_vol = calculate_risk_score(
        Severity.LOW,
        asset_criticality="medium",
        count=60,
    )
    assert score_vol == 40


def test_score_to_severity() -> None:
    assert score_to_severity(95) == Severity.CRITICAL
    assert score_to_severity(80) == Severity.HIGH
    assert score_to_severity(60) == Severity.MEDIUM
    assert score_to_severity(30) == Severity.LOW
