"""End-to-end integration tests for simulation, detection, and accuracy evaluation."""

from pathlib import Path

from sentinellog.engine.engine import DetectionEngine
from sentinellog.ingest.reader import discover_log_files, read_lines
from sentinellog.metrics import calculate_metrics
from sentinellog.parsers.registry import detect_file_format, get_parser
from sentinellog.rules.loader import load_rules_from_dir
from sentinellog.simulate.generator import simulate_logs


def test_full_pipeline_simulation_to_detection(tmp_path: Path) -> None:
    """Verify that simulating mixed attacks produces expected alerts and high recall."""
    sim_dir = tmp_path / "simulated"
    records = simulate_logs(scenario="mixed", out_dir=sim_dir, seed=42, total_lines=5000)
    assert len(records) >= 3

    rules = load_rules_from_dir("rules")
    engine = DetectionEngine(rules=rules)

    all_files = discover_log_files(sim_dir)
    alerts = []

    for f in all_files:
        fmt = detect_file_format(f)
        try:
            parser = get_parser(fmt)
        except KeyError:
            continue

        for line_num, line in read_lines(f):
            event = parser.parse(line, str(f), line_num)
            if event is not None:
                alerts.extend(engine.process_event(event))
    alerts.extend(engine.flush())

    fired_rule_ids = {a.rule_id for a in alerts}
    assert "SSH-001" in fired_rule_ids
    assert "SSH-002" in fired_rule_ids
    assert "WEB-001" in fired_rule_ids
    assert "WEB-004" in fired_rule_ids
    assert "WEB-006" in fired_rule_ids

    # Evaluate metrics against labels.json
    labels_path = sim_dir / "labels.json"
    metrics = calculate_metrics(labels_path, alerts)
    assert metrics["scenario_recall"] >= 0.8
    assert metrics["alert_precision"] >= 0.7


def test_normal_only_logs_produce_zero_alerts(tmp_path: Path) -> None:
    """Verify clean background logs with no injected attacks trigger zero alerts."""
    clean_dir = tmp_path / "clean"
    # Scenario without attack injections
    simulate_logs(scenario="none", out_dir=clean_dir, seed=42, total_lines=2000)

    rules = load_rules_from_dir("rules")
    engine = DetectionEngine(rules=rules)

    all_files = discover_log_files(clean_dir)
    alerts = []

    for f in all_files:
        fmt = detect_file_format(f)
        try:
            parser = get_parser(fmt)
        except KeyError:
            continue

        for line_num, line in read_lines(f):
            event = parser.parse(line, str(f), line_num)
            if event is not None:
                alerts.extend(engine.process_event(event))
    alerts.extend(engine.flush())

    assert len(alerts) == 0
