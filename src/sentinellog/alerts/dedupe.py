"""Alert deduplication and coalescing across sliding time windows."""

from collections.abc import Iterable

from sentinellog.alerts.scoring import calculate_risk_score
from sentinellog.models import Alert


def _make_alert_fingerprint(alert: Alert) -> tuple[str, str]:
    """Compute deterministic fingerprint for an alert based on rule ID and sorted entities."""
    entity_parts = []
    for k in sorted(alert.entities.keys()):
        vals = ",".join(sorted(alert.entities[k]))
        entity_parts.append(f"{k}={vals}")
    entity_str = ";".join(entity_parts)
    return (alert.rule_id, entity_str)


class AlertDeduplicator:
    """Sliding-window deduplicator aggregating duplicate alerts for identical entities."""

    def __init__(self, window_seconds: int = 300, max_evidence: int = 50) -> None:
        self.window_seconds = window_seconds
        self.max_evidence = max_evidence
        # Map: fingerprint -> Alert
        self._active_alerts: dict[tuple[str, str], Alert] = {}

    def process_alert(self, new_alert: Alert) -> None:
        """Incorporate an incoming alert into the deduplication window."""
        fp = _make_alert_fingerprint(new_alert)

        if fp in self._active_alerts:
            existing = self._active_alerts[fp]
            diff = (new_alert.first_seen - existing.last_seen).total_seconds()

            if diff <= self.window_seconds:
                # Merge into existing alert
                merged_count = existing.count + new_alert.count
                new_score = calculate_risk_score(
                    base_severity=existing.severity,
                    count=merged_count,
                )
                combined_evidence = (existing.evidence + new_alert.evidence)[-self.max_evidence :]

                updated = existing.model_copy(
                    update={
                        "first_seen": min(existing.first_seen, new_alert.first_seen),
                        "last_seen": max(existing.last_seen, new_alert.last_seen),
                        "count": merged_count,
                        "score": max(existing.score, new_score),
                        "evidence": combined_evidence,
                    }
                )
                self._active_alerts[fp] = updated
                return

        # New active window for this fingerprint
        self._active_alerts[fp] = new_alert

    def flush(self) -> list[Alert]:
        """Flush and return all aggregated alerts, clearing the internal cache."""
        results = sorted(self._active_alerts.values(), key=lambda a: a.first_seen)
        self._active_alerts.clear()
        return results


def deduplicate_alerts(
    alerts: Iterable[Alert],
    window_seconds: int = 300,
    max_evidence: int = 50,
) -> list[Alert]:
    """Batch helper deduplicating a list of alerts within a sliding window."""
    deduper = AlertDeduplicator(window_seconds=window_seconds, max_evidence=max_evidence)
    for alert in sorted(alerts, key=lambda a: a.first_seen):
        deduper.process_alert(alert)
    return deduper.flush()
