"""Mathematical alert risk scoring engine calculating composite risk values."""

from sentinellog.models import Severity

BASE_SEVERITY_SCORES: dict[Severity | str, int] = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 75,
    Severity.MEDIUM: 50,
    Severity.LOW: 25,
    "critical": 90,
    "high": 75,
    "medium": 50,
    "low": 25,
}

ASSET_MODIFIERS: dict[str, int] = {
    "critical": 15,
    "high": 10,
    "medium": 5,
    "low": 0,
}


def calculate_risk_score(
    base_severity: Severity | str,
    asset_criticality: str | None = None,
    is_threat_intel_match: bool = False,
    count: int = 1,
) -> int:
    """Calculate composite risk score between 1 and 100 based on multiple risk dimensions."""
    score = BASE_SEVERITY_SCORES.get(base_severity, 50)

    # Asset criticality modifier
    if asset_criticality:
        clean_crit = asset_criticality.strip().lower()
        score += ASSET_MODIFIERS.get(clean_crit, 0)

    # Threat Intelligence hit modifier
    if is_threat_intel_match:
        score += 20

    # Volume and recurrence modifier
    if count >= 50:
        score += 10
    elif count >= 10:
        score += 5

    return max(1, min(100, score))


def score_to_severity(score: int) -> Severity:
    """Derive adjusted Severity level from numeric risk score."""
    if score >= 90:
        return Severity.CRITICAL
    if score >= 75:
        return Severity.HIGH
    if score >= 50:
        return Severity.MEDIUM
    return Severity.LOW
