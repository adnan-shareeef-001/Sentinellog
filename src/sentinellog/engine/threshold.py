"""Sliding time-window threshold detection engine with distinct entity counting."""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime

from sentinellog.engine.match import (
    BASE_SEVERITY_SCORES,
    matches_exceptions,
    matches_filter,
)
from sentinellog.models import Alert, Event, EvidenceRef
from sentinellog.rules.schema import Rule, parse_window_seconds


@dataclass
class WindowEvent:
    """Individual event record within a sliding window."""

    timestamp: datetime
    distinct_val: str | None
    evidence: EvidenceRef
    event: Event


@dataclass
class KeyState:
    """State tracked for a specific group_by entity key."""

    events: deque[WindowEvent] = field(default_factory=deque)
    cooldown_until: datetime | None = None
    last_alert: Alert | None = None


class ThresholdEngine:
    """Engine for evaluating sliding-window threshold detection rules."""

    def __init__(self) -> None:
        # Map: (rule_id, group_key_tuple) -> KeyState
        self._states: dict[tuple[str, tuple[str, ...]], KeyState] = defaultdict(KeyState)

    def _extract_group_key(self, event: Event, group_by: list[str]) -> tuple[str, ...]:
        """Extract tuple of grouped entity values from an Event."""
        if not group_by:
            # Default grouping by src_ip if available, else host, else 'global'
            val = event.src_ip or event.host or "global"
            return (val,)
        return tuple(str(getattr(event, field_name, None) or "none") for field_name in group_by)

    def evaluate(self, rule: Rule, event: Event) -> Alert | None:
        """Evaluate a threshold rule against an Event.

        Maintains sliding time-window deque per group key and fires when threshold is met.
        """
        if rule.type != "threshold":
            return None

        # Check log_source compatibility
        if rule.log_source != "any" and rule.log_source != event.source_type:
            return None

        # Check exceptions
        if matches_exceptions(event, rule.exceptions):
            return None

        # Check filter
        if not matches_filter(event, rule.detection.filter):
            return None

        detection = rule.detection
        threshold = detection.threshold or 1
        window_seconds = parse_window_seconds(detection.window) or 300
        distinct_field = detection.distinct

        group_key = self._extract_group_key(event, detection.group_by)
        state_key = (rule.id, group_key)
        state = self._states[state_key]

        ev_ref = EvidenceRef(file=event.file, line_number=event.line_number, raw=event.raw)
        distinct_val = str(getattr(event, distinct_field, None)) if distinct_field else None

        # Add event to deque
        state.events.append(
            WindowEvent(
                timestamp=event.timestamp,
                distinct_val=distinct_val,
                evidence=ev_ref,
                event=event,
            )
        )

        # Evict events outside sliding window relative to current event timestamp
        current_ts = event.timestamp
        while state.events:
            oldest_ts = state.events[0].timestamp
            diff_seconds = (current_ts - oldest_ts).total_seconds()
            if diff_seconds > window_seconds:
                state.events.popleft()
            else:
                break

        # Check cooldown: if currently in cooldown for this key, suppress duplicate alert
        if state.cooldown_until and current_ts < state.cooldown_until:
            if state.last_alert:
                state.last_alert.last_seen = current_ts
                state.last_alert.count += 1
                if len(state.last_alert.evidence) < 50:
                    state.last_alert.evidence.append(ev_ref)
            return None

        # Calculate current count or distinct count
        if distinct_field:
            unique_vals = {e.distinct_val for e in state.events if e.distinct_val is not None}
            current_metric = len(unique_vals)
        else:
            current_metric = len(state.events)

        if current_metric >= threshold:
            first_ts = state.events[0].timestamp
            total_count = len(state.events)

            # Build entities
            entities: dict[str, list[str]] = {}
            for e in state.events:
                if e.event.src_ip:
                    entities.setdefault("src_ip", []).append(e.event.src_ip)
                if e.event.user:
                    entities.setdefault("user", []).append(e.event.user)
                if e.event.host:
                    entities.setdefault("host", []).append(e.event.host)

            # Deduplicate entity lists
            cleaned_entities = {k: sorted(set(v)) for k, v in entities.items()}

            score = BASE_SEVERITY_SCORES.get(rule.severity.value, 50)
            first_iso = first_ts.isoformat()
            last_iso = current_ts.isoformat()

            distinct_msg = (
                f" ({current_metric} distinct {distinct_field}s)" if distinct_field else ""
            )
            explanation = (
                f"{rule.name}: {total_count} matching events{distinct_msg} from {cleaned_entities} "
                f"between {first_iso} and {last_iso}. {rule.description}"
            )

            # Take up to 50 evidence records
            evidence_sample = [e.evidence for e in list(state.events)[-50:]]

            alert = Alert(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                score=score,
                first_seen=first_ts,
                last_seen=current_ts,
                count=total_count,
                entities=cleaned_entities,
                evidence=evidence_sample,
                mitre={"tactic": rule.mitre.tactic, "technique": rule.mitre.technique},
                explanation=explanation,
                recommended_action=rule.response.recommended_action,
            )

            # Enter cooldown until window has elapsed from last seen
            import datetime as dt_mod

            state.cooldown_until = current_ts + dt_mod.timedelta(seconds=window_seconds)
            state.last_alert = alert

            return alert

        return None
