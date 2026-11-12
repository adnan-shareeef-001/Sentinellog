"""Unit tests for the rules and scan CLI commands."""

import json
from pathlib import Path

from typer.testing import CliRunner

from sentinellog.cli import app

runner = CliRunner(env={"COLUMNS": "160"})


def test_cli_rules_list() -> None:
    """Verify rules list renders all loaded rules."""
    result = runner.invoke(app, ["rules", "list", "--rules", "rules"])
    assert result.exit_code == 0
    assert "SSH-001" in result.stdout
    assert "WEB-001" in result.stdout
    assert "Detection Rules Catalog" in result.stdout


def test_cli_rules_validate() -> None:
    """Verify rules validate command passes on valid rules catalog."""
    result = runner.invoke(app, ["rules", "validate", "--rules", "rules"])
    assert result.exit_code == 0
    assert "Success: Validated" in result.stdout


def test_cli_rules_test() -> None:
    """Verify rules test evaluates fixtures and passes."""
    result = runner.invoke(app, ["rules", "test", "--rules", "rules"])
    assert result.exit_code == 0
    assert "rules passed fixture testing!" in result.stdout


def test_cli_rules_show() -> None:
    """Verify rules show displays rule YAML definition."""
    result = runner.invoke(app, ["rules", "show", "SSH-001", "--rules", "rules"])
    assert result.exit_code == 0
    assert "Rule Definition: SSH-001" in result.stdout
    assert "auth_failure" in result.stdout


def test_cli_scan(tmp_path: Path) -> None:
    """Verify scan executes on samples and exports to JSON."""
    out_json = tmp_path / "alerts.json"
    result = runner.invoke(
        app,
        ["scan", "data/samples", "--rules", "rules", "--out", str(out_json)],
    )
    assert result.exit_code == 0
    assert "Detected Security Alerts" in result.stdout
    assert "Scan Execution Summary" in result.stdout
    assert out_json.is_file()

    with open(out_json, encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, list)
    assert len(data) >= 1
    assert any(a["rule_id"] == "WEB-001" for a in data)
