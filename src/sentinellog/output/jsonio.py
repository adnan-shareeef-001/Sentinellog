"""JSON serialization utilities for SentinelLog alerts and scan outputs."""

import json
from collections.abc import Sequence
from pathlib import Path

from sentinellog.models import Alert


def alerts_to_dicts(alerts: Sequence[Alert]) -> list[dict[str, object]]:
    """Convert a sequence of Alert models to JSON-serializable dictionaries."""
    return [alert.model_dump(mode="json") for alert in alerts]


def dump_alerts_json(alerts: Sequence[Alert], file_path: Path | str) -> None:
    """Write alerts list to a JSON file."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = alerts_to_dicts(alerts)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
