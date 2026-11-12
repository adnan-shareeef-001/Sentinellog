"""Unit tests for the SentinelLog CLI interface."""

from typer.testing import CliRunner

from sentinellog import __version__
from sentinellog.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    """Verify that --version outputs the correct version and exits cleanly."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_cli_help() -> None:
    """Verify that --help renders CLI documentation and commands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "doctor" in result.stdout
    assert "scan" in result.stdout
    assert "stats" in result.stdout
    assert "rules" in result.stdout
    assert "alerts" in result.stdout


def test_cli_doctor() -> None:
    """Verify that doctor command executes diagnostics successfully."""
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "SentinelLog Diagnostic Doctor" in result.stdout
    assert "System Diagnostics" in result.stdout
    assert "Python Runtime" in result.stdout


def test_cli_rules_help() -> None:
    """Verify that rules subcommand renders help."""
    result = runner.invoke(app, ["rules", "--help"])
    assert result.exit_code == 0
    assert "validate" in result.stdout
    assert "list" in result.stdout
    assert "test" in result.stdout
    assert "show" in result.stdout


def test_cli_alerts_help() -> None:
    """Verify that alerts subcommand renders help."""
    result = runner.invoke(app, ["alerts", "--help"])
    assert result.exit_code == 0
    assert "list" in result.stdout
    assert "mark" in result.stdout


def test_cli_stats() -> None:
    """Verify stats command runs and reports parsed counts on sample data."""
    result = runner.invoke(app, ["stats", "data/samples"])
    assert result.exit_code == 0
    assert "Ingestion & Parsing Summary" in result.stdout
    assert "Total Files Inspected" in result.stdout
    assert "Events Parsed" in result.stdout
