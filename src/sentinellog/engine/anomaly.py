"""Anomaly detection engines: off-hours schedule checks and rolling Z-score rate spikes."""

import math
from collections import defaultdict, deque
from datetime import datetime, time

from sentinellog.engine.match import (
    BASE_SEVERITY_SCORES,
    matches_exceptions,
    matches_filter,
)
from sentinellog.models import Alert, Event, EvidenceRef
from sentinellog.rules.schema import Rule, parse_window_seconds

DAY_MAP = {
    "mon": 0,
    "monday": 0,
    "tue": 1,
    "tuesday": 1,
    "wed": 2,
    "wednesday": 2,
    "thu": 3,
    "thursday": 3,
    "fri": 4,
    "friday": 4,
    "sat": 5,
    "saturday": 5,
    "sun": 6,
    "sunday": 6,
}


def _parse_time_str(val: str, default: time) -> time:
    """Parse HH:MM or HH:MM:SS string to datetime.time."""
    try:
        parts = [int(p) for p in val.strip().split(":")]
        if len(parts) == 2:
            return time(parts[0], parts[1])
        if len(parts) == 3:
            return time(parts[0], parts[1], parts[2])
    except (ValueError, AttributeError):
        pass
    return default


class AnomalyEngine:
    """Detects statistical volume rate spikes and temporal off-hours activity anomalies."""

    def __init__(self) -> None:
        # Rate spike state: (rule_id, entity_key) -> deque of (timestamp, EvidenceRef)
        self._rate_windows: dict[tuple[str, str], deque[tuple[datetime, EvidenceRef]]] = (
            defaultdict(deque)
        )
        # Rate spike historical bucket counts for Z-score calculation
        self._historical_counts: dict[tuple[str, str], list[int]] = defaultdict(list)
        # Cooldown tracking: (rule_id, entity_key) -> last_alert_time
        self._cooldowns: dict[tuple[str, str], datetime] = {}

    def _extract_group_key(self, event: Event, group_by: list[str]) -> str:
        """Extract composite grouping key or default to global."""
        if not group_by:
            return event.src_ip or event.host or "global"
        parts = []
        for f in group_by:
            val = getattr(event, f, None)
            parts.append(f"{f}:{val or 'none'}")
        return "|".join(parts)

    def evaluate_offhours(self, rule: Rule, event: Event) -> Alert | None:
        """Check if an event matching rule criteria occurred outside designated business hours."""
        if not matches_filter(event, rule.detection.filter):
            return None

        hours_cfg = rule.detection.hours or {}
        start_t = _parse_time_str(str(hours_cfg.get("start", "08:00")), time(8, 0))
        end_t = _parse_time_str(str(hours_cfg.get("end", "18:00")), time(18, 0))

        raw_days = hours_cfg.get("days", ["mon", "tue", "wed", "thu", "fri"])
        allowed_days = {DAY_MAP.get(str(d).lower().strip(), 0) for d in raw_days}

        # Check weekday and time
        dt = event.timestamp
        is_allowed_day = dt.weekday() in allowed_days
        event_t = dt.time()
        is_allowed_time = start_t <= event_t <= end_t

        if is_allowed_day and is_allowed_time:
            # Within normal business hours
            return None

        # Anomaly detected: Off-hours activity!
        entities: dict[str, list[str]] = {}
        if event.src_ip:
            entities["src_ip"] = [event.src_ip]
        if event.user:
            entities["user"] = [event.user]
        if event.host:
            entities["host"] = [event.host]

        ev_ref = EvidenceRef(file=event.file, line_number=event.line_number, raw=event.raw)
        score = BASE_SEVERITY_SCORES.get(rule.severity.value, 50)
        day_name = dt.strftime("%A")
        time_str = dt.strftime("%H:%M:%S UTC")

        explanation = (
            f"{rule.name}: off-hours activity detected on {day_name} at {time_str} from "
            f"{entities}. Expected business schedule: {start_t.strftime('%H:%M')}-"
            f"{end_t.strftime('%H:%M')} on {', '.join(str(d).capitalize() for d in raw_days)}. "
            f"{rule.description}"
        )

        return Alert(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            score=score,
            first_seen=dt,
            last_seen=dt,
            count=1,
            entities=entities,
            evidence=[ev_ref],
            mitre={"tactic": rule.mitre.tactic, "technique": rule.mitre.technique},
            explanation=explanation,
            recommended_action=rule.response.recommended_action,
        )

    def evaluate_rate_spike(self, rule: Rule, event: Event) -> Alert | None:
        """Detect abnormal event frequency bursts using moving window statistical bounds."""
        if not matches_filter(event, rule.detection.filter):
            return None

        group_key = self._extract_group_key(event, rule.detection.group_by)
        state_key = (rule.id, group_key)

        window_seconds = parse_window_seconds(rule.detection.window) or 300
        z_threshold = rule.detection.z or 3.0
        min_threshold = rule.detection.threshold or 5

        # Check cooldown
        if state_key in self._cooldowns:
            last_alert = self._cooldowns[state_key]
            if (event.timestamp - last_alert).total_seconds() < window_seconds:
                return None

        dq = self._rate_windows[state_key]
        ev_ref = EvidenceRef(file=event.file, line_number=event.line_number, raw=event.raw)
        dq.append((event.timestamp, ev_ref))

        # Evict events outside current sliding window
        cutoff = event.timestamp.timestamp() - window_seconds
        while dq and dq[0][0].timestamp() < cutoff:
            dq.popleft()

        current_count = len(dq)

        # Statistical evaluation: check against historical buckets or fallback to threshold
        history = self._historical_counts[state_key]
        is_spike = False

        if len(history) >= 3:
            mean = sum(history) / len(history)
            variance = sum((x - mean) ** 2 for x in history) / len(history)
            std_dev = math.sqrt(variance)
            threshold_val = mean + (z_threshold * max(std_dev, 1.0))
            if current_count >= threshold_val and current_count >= min_threshold:
                is_spike = True
        else:
            # Baseline learning phase: use specified threshold
            if current_count >= min_threshold:
                is_spike = True

        if is_spike:
            # Record current count in history for future comparison
            history.append(current_count)
            if len(history) > 20:
                history.pop(0)

            self._cooldowns[state_key] = event.timestamp

            first_seen = dq[0][0]
            last_seen = event.timestamp
            all_evidence = [item[1] for item in dq]

            entities: dict[str, list[str]] = {}
            if event.src_ip:
                entities["src_ip"] = [event.src_ip]
            if event.user:
                entities["user"] = [event.user]
            if event.host:
                entities["host"] = [event.host]

            score = BASE_SEVERITY_SCORES.get(rule.severity.value, 70)
            explanation = (
                f"{rule.name}: abnormal rate spike ({current_count} events in {window_seconds}s) "
                f"exceeding expected baseline (Z={z_threshold:.1f}) for {entities}. "
                f"{rule.description}"
            )

            return Alert(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                score=score,
                first_seen=first_seen,
                last_seen=last_seen,
                count=current_count,
                entities=entities,
                evidence=all_evidence[-50:],
                mitre={"tactic": rule.mitre.tactic, "technique": rule.mitre.technique},
                explanation=explanation,
                recommended_action=rule.response.recommended_action,
            )

        return None

    def evaluate(self, rule: Rule, event: Event) -> Alert | None:
        """Evaluate an anomaly detection rule against an event."""
        if rule.type != "anomaly":
            return None

        # Check source compatibility
        if rule.log_source != "any" and rule.log_source != event.source_type:
            return None

        # Check exceptions
        if matches_exceptions(event, rule.exceptions):
            return None

        kind = (rule.detection.kind or "offhours").lower().strip()
        if kind == "offhours":
            return self.evaluate_offhours(rule, event)
        if kind == "rate_spike":
            return self.evaluate_rate_spike(rule, event)

        return None
