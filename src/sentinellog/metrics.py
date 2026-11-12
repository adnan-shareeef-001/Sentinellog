"""Detection validation metrics: scenario recall and alert precision calculator."""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sentinellog.models import Alert


def load_labels(labels_file: Path | str) -> list[dict[str, Any]]:
    """Load ground-truth labels from labels.json."""
    path = Path(labels_file)
    if not path.is_file():
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def calculate_metrics(
    labels_file: Path | str,
    alerts: Sequence[Alert],
) -> dict[str, float]:
    """Calculate scenario recall and alert precision based on ground truth labels.

    - Scenario Recall = Scenarios where all expected_rules fired / Total scenarios
    - Alert Precision = Alerts referencing at least one labeled malicious line / Total alerts
    """
    labels = load_labels(labels_file)
    if not labels:
        return {
            "scenario_recall": 1.0,
            "alert_precision": 1.0,
            "total_scenarios": 0.0,
            "recalled_scenarios": 0.0,
            "total_alerts": float(len(alerts)),
            "tp_alerts": float(len(alerts)),
        }

    # Set of malicious (basename, line_number)
    malicious_lines: set[tuple[str, int]] = set()
    for sc in labels:
        file_name = Path(str(sc.get("file", ""))).name
        for ln in sc.get("line_numbers", []):
            malicious_lines.add((file_name, int(ln)))

    # 1. Calculate Scenario Recall
    total_scenarios = len(labels)
    recalled_scenarios = 0

    all_fired_rule_ids = {alert.rule_id for alert in alerts}

    for sc in labels:
        expected = set(sc.get("expected_rules", []))
        if not expected:
            recalled_scenarios += 1
            continue

        if expected.issubset(all_fired_rule_ids):
            recalled_scenarios += 1

    scenario_recall = (recalled_scenarios / total_scenarios) if total_scenarios > 0 else 1.0

    # 2. Calculate Alert Precision
    total_alerts = len(alerts)
    tp_alerts = 0

    for alert in alerts:
        is_tp = False
        for ev in alert.evidence:
            ev_file = Path(ev.file).name
            if (ev_file, ev.line_number) in malicious_lines:
                is_tp = True
                break
        if is_tp:
            tp_alerts += 1

    alert_precision = (tp_alerts / total_alerts) if total_alerts > 0 else 1.0

    return {
        "scenario_recall": scenario_recall,
        "alert_precision": alert_precision,
        "total_scenarios": float(total_scenarios),
        "recalled_scenarios": float(recalled_scenarios),
        "total_alerts": float(total_alerts),
        "tp_alerts": float(tp_alerts),
    }
