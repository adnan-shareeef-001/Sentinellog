"""Smoke tests verifying baseline imports and Typer CLI execution."""

from typer.testing import CliRunner

from sentinellog import __version__
from sentinellog.cli import app

runner = CliRunner()


def test_version_string() -> None:
    """Verify package version is defined."""
    assert __version__ == "0.1.0"


def test_cli_help() -> None:
    """Verify CLI --help returns exit code 0 and lists core subcommands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "sentinellog" in result.output.lower()
    assert "scan" in result.output
    assert "tail" in result.output
    assert "simulate" in result.output
    assert "stats" in result.output
    assert "report" in result.output
    assert "doctor" in result.output
    assert "rules" in result.output
    assert "alerts" in result.output


def test_cli_doctor() -> None:
    """Verify doctor command runs diagnostic checks."""
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "SentinelLog Diagnostic Doctor" in result.output
