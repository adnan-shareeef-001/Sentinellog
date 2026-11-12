"""Multi-event state machine sequence correlation engine."""

from collections import defaultdict
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
class SequenceState:
    """State machine tracking progress across multi-step sequences for an entity."""

    current_step: int = 0
    current_count: int = 0
    start_time: datetime | None = None
    evidence: list[EvidenceRef] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)


class SequenceEngine:
    """State machine engine evaluating ordered multi-event attack sequences."""

    def __init__(self) -> None:
        # Map: (rule_id, entity_key_tuple) -> SequenceState
        self._states: dict[tuple[str, tuple[str, ...]], SequenceState] = defaultdict(SequenceState)

    def _extract_same_key(self, event: Event, same_fields: list[str]) -> tuple[str, ...] | None:
        """Extract entity correlation key (e.g. src_ip). Return None if entity is undefined."""
        if not same_fields:
            default_val = event.src_ip or event.host or "global"
            return (default_val,)

        key_parts = []
        for f in same_fields:
            field_val = getattr(event, f, None)
            if not field_val:
                return None
            key_parts.append(str(field_val))
        return tuple(key_parts)

    def evaluate(self, rule: Rule, event: Event) -> Alert | None:
        """Evaluate an Event against a sequence rule state machine."""
        if rule.type != "sequence":
            return None

        # Check source compatibility
        if rule.log_source != "any" and rule.log_source != event.source_type:
            return None

        # Check exceptions
        if matches_exceptions(event, rule.exceptions):
            return None

        detection = rule.detection
        steps = detection.steps
        if not steps:
            return None

        same_key = self._extract_same_key(event, detection.same)
        if same_key is None:
            return None

        state_key = (rule.id, same_key)
        state = self._states[state_key]

        window_seconds = parse_window_seconds(detection.window) or 600

        # Check if active window expired
        if state.start_time is not None:
            diff_sec = (event.timestamp - state.start_time).total_seconds()
            if diff_sec > window_seconds:
                # Reset state
                state = SequenceState()
                self._states[state_key] = state

        ev_ref = EvidenceRef(file=event.file, line_number=event.line_number, raw=event.raw)
        step = steps[state.current_step]

        # Test if event matches current step filter
        if matches_filter(event, step.filter):
            if state.start_time is None:
                state.start_time = event.timestamp

            state.current_count += 1
            state.evidence.append(ev_ref)
            state.events.append(event)

            if state.current_count >= step.min_count:
                # Advance to next step
                if state.current_step + 1 == len(steps):
                    # Sequence Completed! Emit Alert
                    first_ts = state.start_time or event.timestamp
                    last_ts = event.timestamp

                    entities: dict[str, list[str]] = {}
                    for e in state.events:
                        if e.src_ip:
                            entities.setdefault("src_ip", []).append(e.src_ip)
                        if e.user:
                            entities.setdefault("user", []).append(e.user)
                        if e.host:
                            entities.setdefault("host", []).append(e.host)
                    cleaned_entities = {k: sorted(set(v)) for k, v in entities.items()}

                    score = BASE_SEVERITY_SCORES.get(rule.severity.value, 70)
                    first_iso = first_ts.isoformat()
                    last_iso = last_ts.isoformat()

                    explanation = (
                        f"{rule.name}: multi-stage sequence ({len(steps)} steps) completed from "
                        f"{cleaned_entities} between {first_iso} and {last_iso}. {rule.description}"
                    )

                    alert = Alert(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        score=score,
                        first_seen=first_ts,
                        last_seen=last_ts,
                        count=len(state.events),
                        entities=cleaned_entities,
                        evidence=state.evidence[-50:],
                        mitre={"tactic": rule.mitre.tactic, "technique": rule.mitre.technique},
                        explanation=explanation,
                        recommended_action=rule.response.recommended_action,
                    )

                    # Reset state machine for this entity
                    del self._states[state_key]
                    return alert

                # Move to next stage
                state.current_step += 1
                state.current_count = 0

        return None
