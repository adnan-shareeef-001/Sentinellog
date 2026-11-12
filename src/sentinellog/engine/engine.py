"""Core detection engine orchestrator with timestamp reordering buffer."""

from collections.abc import Iterator
from typing import Any

from sentinellog.engine.match import MatchEngine, matches_allowlist
from sentinellog.engine.sequence import SequenceEngine
from sentinellog.engine.threshold import ThresholdEngine
from sentinellog.models import Alert, Event
from sentinellog.rules.schema import Rule

MAX_BUFFER_SIZE = 1000
MAX_BUFFER_SECONDS = 60


class DetectionEngine:
    """Orchestrates event ordering and evaluation across all detection sub-engines."""

    def __init__(
        self,
        rules: list[Rule],
        allowlist: dict[str, Any] | None = None,
        buffer_size: int = MAX_BUFFER_SIZE,
        buffer_seconds: int = MAX_BUFFER_SECONDS,
    ) -> None:
        self.rules = [r for r in rules if r.enabled]
        self.allowlist = allowlist or {}
        self.buffer_size = buffer_size
        self.buffer_seconds = buffer_seconds

        # Detection sub-engines
        self.match_engine = MatchEngine()
        self.threshold_engine = ThresholdEngine()
        self.sequence_engine = SequenceEngine()

        # Reorder buffer
        self._buffer: list[Event] = []

    def _process_single_event(self, event: Event) -> list[Alert]:
        """Evaluate a single ordered event against all loaded rules."""
        if matches_allowlist(event, self.allowlist):
            return []

        alerts: list[Alert] = []
        for rule in self.rules:
            # Check source compatibility
            if rule.log_source != "any" and rule.log_source != event.source_type:
                continue

            alert: Alert | None = None
            if rule.type == "match":
                alert = self.match_engine.evaluate(rule, event)
            elif rule.type == "threshold":
                alert = self.threshold_engine.evaluate(rule, event)
            elif rule.type == "sequence":
                alert = self.sequence_engine.evaluate(rule, event)

            if alert is not None:
                alerts.append(alert)

        return alerts

    def process_event(self, event: Event) -> list[Alert]:
        """Ingest an event into the reorder buffer and return any ready alerts."""
        self._buffer.append(event)
        alerts: list[Alert] = []

        # Check if buffer needs draining
        if len(self._buffer) >= self.buffer_size:
            # Sort buffer by event timestamp
            self._buffer.sort(key=lambda e: e.timestamp)
            # Drain oldest half of buffer
            drain_count = len(self._buffer) // 2
            for _ in range(drain_count):
                oldest_event = self._buffer.pop(0)
                alerts.extend(self._process_single_event(oldest_event))
        elif len(self._buffer) > 1:
            newest_ts = event.timestamp
            oldest_ts = self._buffer[0].timestamp
            diff_sec = (newest_ts - oldest_ts).total_seconds()
            if diff_sec > self.buffer_seconds:
                self._buffer.sort(key=lambda e: e.timestamp)
                oldest_event = self._buffer.pop(0)
                alerts.extend(self._process_single_event(oldest_event))

        return alerts

    def flush(self) -> list[Alert]:
        """Drain all remaining events from the reorder buffer in timestamp order."""
        if not self._buffer:
            return []

        self._buffer.sort(key=lambda e: e.timestamp)
        alerts: list[Alert] = []
        while self._buffer:
            event = self._buffer.pop(0)
            alerts.extend(self._process_single_event(event))

        return alerts

    def process_stream(self, events: Iterator[Event]) -> list[Alert]:
        """Process an entire stream of events and return all generated alerts."""
        alerts: list[Alert] = []
        for event in events:
            alerts.extend(self.process_event(event))
        alerts.extend(self.flush())
        return alerts
