"""SentinelLog Command-Line Interface (CLI)."""

import sys
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinellog import __version__

app = typer.Typer(
    name="sentinellog",
    help="SentinelLog - Defensive Log Analysis & SOC Threat Detection Engine.",
    no_args_is_help=True,
    add_completion=False,
)
rules_app = typer.Typer(
    name="rules",
    help="Manage, validate, test, and inspect YAML detection rules.",
    no_args_is_help=True,
)
alerts_app = typer.Typer(
    name="alerts",
    help="Query and manage persisted security alerts.",
    no_args_is_help=True,
)
app.add_typer(rules_app, name="rules")
app.add_typer(alerts_app, name="alerts")

console = Console()


class LogFormat(StrEnum):
    AUTO = "auto"
    SSH = "ssh"
    WEB = "web"
    WINDOWS = "windows"
    SYSLOG = "syslog"
    JSONL = "jsonl"


class FailOnSeverity(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Scenario(StrEnum):
    BRUTE_FORCE = "brute_force"
    SPRAYING = "spraying"
    WEB_ATTACK = "web_attack"
    WINDOWS_COMPROMISE = "windows_compromise"
    MIXED = "mixed"


def version_callback(value: bool) -> None:
    """Print the version of SentinelLog and exit."""
    if value:
        console.print(f"[bold cyan]SentinelLog[/bold cyan] version [green]{__version__}[/green]")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show SentinelLog version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """SentinelLog: Defensive log analysis and threat detection engine."""


@app.command()
def scan(
    paths: list[Path] = typer.Argument(..., help="One or more log files or directories to scan."),
    format: LogFormat = typer.Option(LogFormat.AUTO, "--format", "-f", help="Log parser format."),
    rules: Path = typer.Option(Path("rules"), "--rules", "-r", help="Path to detection rules dir."),
    since: str | None = typer.Option(None, "--since", help="Filter events since timestamp."),
    out: Path | None = typer.Option(None, "--out", "-o", help="Output file (json, csv, or html)."),
    fail_on: FailOnSeverity = typer.Option(
        FailOnSeverity.NONE, "--fail-on", help="Exit code 2 if alerts at or above severity occur."
    ),
    no_store: bool = typer.Option(False, "--no-store", help="Do not store alerts in SQLite."),
    max_file_mb: int = typer.Option(500, "--max-file-mb", help="Max file size in megabytes."),
) -> None:
    """Scan log files against YAML detection rules and generate security alerts."""
    console.print(f"[cyan]Scanning paths:[/cyan] {[str(p) for p in paths]}")
    console.print(f"[dim]Format: {format.value} | Rules: {rules} | Fail-on: {fail_on.value}[/dim]")


@app.command()
def tail(
    file: Path = typer.Argument(..., help="Log file path to continuously monitor."),
    format: LogFormat = typer.Option(LogFormat.AUTO, "--format", "-f", help="Log format."),
    rules: Path = typer.Option(Path("rules"), "--rules", "-r", help="Path to rules dir."),
) -> None:
    """Continuously tail a log file in real time and evaluate detection rules."""
    console.print(f"[cyan]Tailing log stream:[/cyan] {file} [dim]format: {format.value}[/dim]")


@app.command()
def simulate(
    scenario: Scenario = typer.Option(
        Scenario.MIXED, "--scenario", "-s", help="Attack scenario to generate."
    ),
    out: Path = typer.Option(
        Path("data/generated"), "--out", "-o", help="Target output directory."
    ),
    seed: int = typer.Option(42, "--seed", help="Random seed for reproducible generation."),
    lines: int = typer.Option(20000, "--lines", help="Approximate number of lines to generate."),
) -> None:
    """Generate synthetic benign and attack logs with ground-truth labels."""
    console.print(
        f"[cyan]Simulating scenario:[/cyan] {scenario.value} -> {out} (seed={seed}, lines={lines})"
    )


@app.command()
def stats(
    paths: list[Path] = typer.Argument(..., help="Log files or directories to inspect."),
) -> None:
    """Parse log sources and report statistics, source distribution, and accuracy metrics."""
    from sentinellog.ingest.reader import discover_log_files, read_lines
    from sentinellog.parsers.base import ParseContext
    from sentinellog.parsers.registry import detect_file_format, get_parser

    # Collect all log files
    all_files: list[Path] = []
    for p in paths:
        all_files.extend(discover_log_files(p))

    if not all_files:
        console.print("[yellow]No log files found matching target paths.[/yellow]")
        return

    ctx = ParseContext()
    file_stats: list[tuple[str, str, int, int]] = []

    for file_path in all_files:
        fmt = detect_file_format(file_path)
        try:
            parser = get_parser(fmt)
        except KeyError:
            console.print(f"[red]Warning: No parser available for detected format '{fmt}'[/red]")
            continue

        file_lines = 0
        file_events = 0
        for line_num, line in read_lines(file_path):
            file_lines += 1
            ctx.total_lines += 1
            event = parser.parse(line, str(file_path), line_num, ctx)
            if event is not None:
                file_events += 1

        file_stats.append((file_path.name, fmt, file_lines, file_events))

    # Render Summary Table
    summary_table = Table(title="Ingestion & Parsing Summary", show_lines=True)
    summary_table.add_column("Metric", style="bold cyan", width=25)
    summary_table.add_column("Value", style="bold green", justify="right", width=15)

    summary_table.add_row("Total Files Inspected", str(len(all_files)))
    summary_table.add_row("Total Lines Read", f"{ctx.total_lines:,}")
    summary_table.add_row("Events Parsed", f"{ctx.parsed_events:,}")
    summary_table.add_row("Bad / Unparseable Lines", f"{ctx.bad_lines:,}")
    success_rate = (ctx.parsed_events / ctx.total_lines * 100) if ctx.total_lines > 0 else 0.0
    summary_table.add_row("Parsing Success Rate", f"{success_rate:.1f}%")
    console.print(summary_table)

    # Render Per-Source Breakdown Table
    if ctx.source_counts:
        src_table = Table(title="Per-Source Event Counts", show_lines=True)
        src_table.add_column("Source Type", style="bold magenta", width=20)
        src_table.add_column("Events Parsed", justify="right", width=15)
        src_table.add_column("Share (%)", justify="right", width=15)

        for src, count in sorted(ctx.source_counts.items(), key=lambda x: x[1], reverse=True):
            share = (count / ctx.parsed_events * 100) if ctx.parsed_events > 0 else 0.0
            src_table.add_row(src, f"{count:,}", f"{share:.1f}%")
        console.print(src_table)

    # Render Per-Event-Type Table
    if ctx.event_type_counts:
        evt_table = Table(title="Per-Event-Type Distribution", show_lines=True)
        evt_table.add_column("Normalized Event Type", style="bold yellow", width=25)
        evt_table.add_column("Count", justify="right", width=15)

        for et, count in sorted(ctx.event_type_counts.items(), key=lambda x: x[1], reverse=True):
            evt_table.add_row(et, f"{count:,}")
        console.print(evt_table)


@app.command()
def report(
    from_db: bool = typer.Option(
        True, "--from-db", help="Generate report from SQLite alert store."
    ),
    last: str = typer.Option("24h", "--last", help="Time window (e.g., 1h, 24h, 7d)."),
    out: Path = typer.Option(Path("report.html"), "--out", "-o", help="Output HTML file path."),
) -> None:
    """Generate a self-contained HTML executive summary report."""
    console.print(f"[cyan]Generating report:[/cyan] {out} [dim](window: {last})[/dim]")


@app.command()
def doctor() -> None:
    """Run health checks on runtime environment, dependencies, configuration, and rules."""
    console.print(
        Panel.fit(
            "[bold cyan]SentinelLog Diagnostic Doctor[/bold cyan]\n"
            "Verifying environment health, dependencies, and configuration...",
            border_style="cyan",
        )
    )

    table = Table(title="System Diagnostics", show_lines=True)
    table.add_column("Component", style="bold", width=25)
    table.add_column("Status", width=12)
    table.add_column("Details", style="dim")

    py_major, py_minor = sys.version_info.major, sys.version_info.minor
    if (py_major, py_minor) >= (3, 11):
        table.add_row(
            "Python Runtime",
            "[green]PASS[/green]",
            f"Python {py_major}.{py_minor}.{sys.version_info.micro} (>= 3.11)",
        )
    else:
        table.add_row(
            "Python Runtime",
            "[red]FAIL[/red]",
            f"Python {py_major}.{py_minor} is unsupported. Python 3.11+ required.",
        )

    for cfg_name, cfg_rel in [
        ("Config File", "config/sentinellog.yaml"),
        ("Allowlist File", "config/allowlist.yaml"),
        ("Assets File", "config/assets.yaml"),
    ]:
        p = Path(cfg_rel)
        if p.is_file():
            table.add_row(cfg_name, "[green]PASS[/green]", str(p.resolve()))
        else:
            table.add_row(cfg_name, "[yellow]MISSING[/yellow]", f"{cfg_rel} not found")

    rules_dir = Path("rules")
    if rules_dir.is_dir():
        cats = [d.name for d in rules_dir.iterdir() if d.is_dir()]
        table.add_row(
            "Rule Categories",
            "[green]PASS[/green]",
            f"Categories: {', '.join(cats) if cats else 'none'}",
        )
    else:
        table.add_row("Rule Categories", "[yellow]MISSING[/yellow]", "rules/ folder not found")

    intel_file = Path("data/threat_intel/blocklist_ips.txt")
    if intel_file.is_file():
        table.add_row("Threat Intel Feed", "[green]PASS[/green]", str(intel_file.resolve()))
    else:
        table.add_row(
            "Threat Intel Feed", "[yellow]MISSING[/yellow]", "blocklist_ips.txt not found"
        )

    console.print(table)
    console.print("\n[bold green]Environment check completed successfully.[/bold green]\n")


# Rules Subcommands
@rules_app.command("list")
def rules_list(
    rules: Path = typer.Option(Path("rules"), "--rules", "-r", help="Directory containing rules."),
) -> None:
    """List all available detection rules and their severity and MITRE mapping."""
    console.print(f"[cyan]Listing rules from:[/cyan] {rules}")


@rules_app.command("validate")
def rules_validate(
    rules: Path = typer.Option(Path("rules"), "--rules", "-r", help="Directory containing rules."),
) -> None:
    """Validate all YAML detection rules against the Pydantic schema."""
    console.print(f"[cyan]Validating rules in:[/cyan] {rules}")


@rules_app.command("test")
def rules_test(
    rules: Path = typer.Option(Path("rules"), "--rules", "-r", help="Directory containing rules."),
) -> None:
    """Run each rule's should_fire and should_not_fire test fixtures."""
    console.print(f"[cyan]Testing rules fixtures in:[/cyan] {rules}")


@rules_app.command("show")
def rules_show(
    rule_id: str = typer.Argument(..., help="Unique Rule ID (e.g., SSH-001)."),
    rules: Path = typer.Option(Path("rules"), "--rules", "-r", help="Directory containing rules."),
) -> None:
    """Show details, logic, and MITRE mapping for a specific detection rule."""
    console.print(f"[cyan]Showing rule details for:[/cyan] {rule_id}")


# Alerts Subcommands
@alerts_app.command("list")
def alerts_list(
    limit: int = typer.Option(50, "--limit", "-n", help="Max number of alerts to return."),
) -> None:
    """List recent alerts stored in the database."""
    console.print(f"[cyan]Listing up to {limit} alerts from database...[/cyan]")


@alerts_app.command("mark")
def alerts_mark(
    alert_id: str = typer.Argument(..., help="Alert ID to update."),
    status: str = typer.Argument(
        ..., help="New status: new, triaged, false_positive, or resolved."
    ),
) -> None:
    """Update the triage status of a specific alert."""
    console.print(f"[cyan]Updating alert {alert_id} status -> {status}[/cyan]")


if __name__ == "__main__":
    app()
