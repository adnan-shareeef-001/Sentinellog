"""SentinelLog Command-Line Interface (CLI)."""

import sys
import time
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
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

SEVERITY_ORDER = {
    "none": -1,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


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
    from sentinellog.engine.engine import DetectionEngine
    from sentinellog.ingest.reader import discover_log_files, read_lines
    from sentinellog.output.console import (
        render_alert_details,
        render_alerts_table,
        render_scan_summary,
    )
    from sentinellog.output.jsonio import dump_alerts_json
    from sentinellog.parsers.base import ParseContext
    from sentinellog.parsers.registry import detect_file_format, get_parser
    from sentinellog.rules.loader import load_allowlist, load_rules_from_dir

    start_time = time.perf_counter()

    # Load rules and allowlist
    loaded_rules = load_rules_from_dir(rules)
    allowlist = load_allowlist()

    if not loaded_rules:
        console.print(f"[yellow]Warning: No detection rules found in '{rules}'[/yellow]")

    engine = DetectionEngine(rules=loaded_rules, allowlist=allowlist)

    # Discover target files
    all_files: list[Path] = []
    for p in paths:
        all_files.extend(discover_log_files(p))

    if not all_files:
        console.print("[yellow]No log files found matching specified paths.[/yellow]")
        return

    ctx = ParseContext()
    all_alerts = []

    for file_path in all_files:
        if format == LogFormat.AUTO:
            fmt_name = detect_file_format(file_path)
        else:
            fmt_name = format.value

        try:
            parser = get_parser(fmt_name)
        except KeyError:
            console.print(f"[red]Skipping {file_path.name}: format '{fmt_name}' unsupported[/red]")
            continue

        for line_num, line in read_lines(file_path, max_file_bytes=max_file_mb * 1024 * 1024):
            ctx.total_lines += 1
            event = parser.parse(line, str(file_path), line_num, ctx)
            if event is not None:
                new_alerts = engine.process_event(event)
                all_alerts.extend(new_alerts)

    # Flush remaining buffered events
    all_alerts.extend(engine.flush())
    runtime = time.perf_counter() - start_time

    # Render outputs
    render_alerts_table(all_alerts)
    if all_alerts:
        render_alert_details(all_alerts, limit=5)
    render_scan_summary(
        events_parsed=ctx.parsed_events,
        bad_lines=ctx.bad_lines,
        rules_loaded=len(loaded_rules),
        alerts=all_alerts,
        runtime_seconds=runtime,
    )

    # Output file export
    if out:
        if out.suffix.lower() == ".json":
            dump_alerts_json(all_alerts, out)
            console.print(f"[green]Exported alerts to {out}[/green]")

    # Check fail-on exit code
    if fail_on != FailOnSeverity.NONE:
        threshold_rank = SEVERITY_ORDER[fail_on.value]
        highest_rank = max(
            (SEVERITY_ORDER.get(a.severity.value, -1) for a in all_alerts), default=-1
        )
        if highest_rank >= threshold_rank:
            raise typer.Exit(code=2)


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
    from sentinellog.simulate.generator import simulate_logs

    console.print(
        f"[cyan]Simulating scenario:[/cyan] [bold]{scenario.value}[/bold] -> [green]{out}[/green] "
        f"[dim](seed={seed}, target_lines={lines})[/dim]"
    )

    records = simulate_logs(
        scenario=scenario.value,
        out_dir=out,
        seed=seed,
        total_lines=lines,
    )

    summary_table = Table(title="Simulation Generation Summary", show_lines=True)
    summary_table.add_column("Scenario Injected", style="bold cyan", width=25)
    summary_table.add_column("Target File", width=15)
    summary_table.add_column("Malicious Lines", justify="right", width=15)
    summary_table.add_column("Expected Rules", style="dim", width=35)

    for rec in records:
        summary_table.add_row(
            rec.scenario,
            rec.file,
            f"{len(rec.line_numbers):,}",
            ", ".join(rec.expected_rules),
        )

    console.print(summary_table)
    resolved_out = out.resolve()
    console.print("\n[bold green]Simulation complete.[/bold green] Logs written to:")
    console.print(f"  [cyan]{resolved_out}[/cyan]\n")


@app.command()
def stats(
    paths: list[Path] = typer.Argument(..., help="Log files or directories to inspect."),
) -> None:
    """Parse log sources and report statistics, source distribution, and accuracy metrics."""
    from sentinellog.ingest.reader import discover_log_files, read_lines
    from sentinellog.parsers.base import ParseContext
    from sentinellog.parsers.registry import detect_file_format, get_parser

    all_files: list[Path] = []
    for p in paths:
        all_files.extend(discover_log_files(p))

    if not all_files:
        console.print("[yellow]No log files found matching target paths.[/yellow]")
        return

    ctx = ParseContext()
    for file_path in all_files:
        fmt = detect_file_format(file_path)
        try:
            parser = get_parser(fmt)
        except KeyError:
            console.print(f"[red]Warning: No parser available for detected format '{fmt}'[/red]")
            continue

        for line_num, line in read_lines(file_path):
            ctx.total_lines += 1
            parser.parse(line, str(file_path), line_num, ctx)

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

    # Check for labels.json beside input paths for accuracy evaluation
    labels_path = None
    for p in paths:
        candidate = (
            p
            if p.name == "labels.json"
            else (p / "labels.json" if p.is_dir() else p.parent / "labels.json")
        )
        if candidate.is_file():
            labels_path = candidate
            break

    if labels_path:
        from sentinellog.engine.engine import DetectionEngine
        from sentinellog.metrics import calculate_metrics
        from sentinellog.rules.loader import load_rules_from_dir

        rules = load_rules_from_dir("rules")
        engine = DetectionEngine(rules=rules)
        eval_alerts = []

        for file_path in all_files:
            fmt = detect_file_format(file_path)
            try:
                parser = get_parser(fmt)
            except KeyError:
                continue

            for line_num, line in read_lines(file_path):
                event = parser.parse(line, str(file_path), line_num)
                if event is not None:
                    eval_alerts.extend(engine.process_event(event))
        eval_alerts.extend(engine.flush())

        metrics = calculate_metrics(labels_path, eval_alerts)

        acc_table = Table(title="Detection Accuracy Benchmark (Ground Truth)", show_lines=True)
        acc_table.add_column("Benchmark Metric", style="bold cyan", width=25)
        acc_table.add_column("Score", style="bold green", justify="right", width=15)
        acc_table.add_column("Notes", style="dim")

        rec_pct = metrics["scenario_recall"] * 100
        prec_pct = metrics["alert_precision"] * 100

        rec_scenarios = int(metrics["recalled_scenarios"])
        tot_scenarios = int(metrics["total_scenarios"])
        tp_alerts = int(metrics["tp_alerts"])
        tot_alerts = int(metrics["total_alerts"])

        acc_table.add_row(
            "Scenario Recall",
            f"{rec_pct:.1f}%",
            f"{rec_scenarios}/{tot_scenarios} scenarios fully detected",
        )
        acc_table.add_row(
            "Alert Precision",
            f"{prec_pct:.1f}%",
            f"{tp_alerts}/{tot_alerts} alerts match labeled attack lines",
        )

        console.print(acc_table)


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
    from sentinellog.output.console import SEVERITY_COLORS
    from sentinellog.rules.loader import load_rules_from_dir

    loaded = load_rules_from_dir(rules)
    if not loaded:
        console.print(f"[yellow]No rules found in '{rules}'[/yellow]")
        return

    table = Table(title=f"Detection Rules Catalog ({len(loaded)} rules)", show_lines=True)
    table.add_column("Rule ID", style="bold cyan", width=10)
    table.add_column("Rule Name", width=35)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Type", width=10)
    table.add_column("Log Source", width=12)
    table.add_column("MITRE ATT&CK", style="dim", width=25)
    table.add_column("Status", justify="center", width=8)

    for r in loaded:
        color = SEVERITY_COLORS.get(r.severity.value, "white")
        styled_sev = f"[{color}]{r.severity.value.upper()}[/{color}]"
        status = "[green]ENABLED[/green]" if r.enabled else "[dim]DISABLED[/dim]"
        mitre_str = f"{r.mitre.technique} ({r.mitre.tactic})"
        table.add_row(r.id, r.name, styled_sev, r.type, r.log_source, mitre_str, status)

    console.print(table)


@rules_app.command("validate")
def rules_validate(
    rules: Path = typer.Option(Path("rules"), "--rules", "-r", help="Directory containing rules."),
) -> None:
    """Validate all YAML detection rules against the Pydantic schema."""
    from sentinellog.rules.loader import load_rules_from_dir

    try:
        loaded = load_rules_from_dir(rules)
    except Exception as e:
        console.print(f"[bold red]Validation Failure:[/bold red] {e}")
        raise typer.Exit(code=3) from e

    if not loaded:
        console.print(f"[yellow]Warning: No rules discovered in '{rules}'[/yellow]")
        raise typer.Exit(code=3)

    console.print(
        f"[bold green]Success: Validated {len(loaded)} rules without errors.[/bold green]"
    )


def _run_rule_fixture(rule_obj: object, fixture_path: Path) -> int:
    """Parse a fixture file and return count of alerts emitted for a specific rule."""
    from sentinellog.engine.engine import DetectionEngine
    from sentinellog.ingest.reader import read_lines
    from sentinellog.parsers.registry import detect_file_format, get_parser
    from sentinellog.rules.schema import Rule

    if not isinstance(rule_obj, Rule):
        return 0
    fmt = detect_file_format(fixture_path)
    parser = get_parser(fmt)
    engine = DetectionEngine(rules=[rule_obj])

    alerts = []
    for line_num, line in read_lines(fixture_path):
        event = parser.parse(line, str(fixture_path), line_num)
        if event is not None:
            alerts.extend(engine.process_event(event))
    alerts.extend(engine.flush())

    return sum(1 for a in alerts if a.rule_id == rule_obj.id)


@rules_app.command("test")
def rules_test(
    rules: Path = typer.Option(Path("rules"), "--rules", "-r", help="Directory containing rules."),
) -> None:
    """Run each rule's should_fire and should_not_fire test fixtures."""
    from sentinellog.rules.loader import load_rules_from_dir

    loaded = load_rules_from_dir(rules)
    if not loaded:
        console.print(f"[yellow]No rules found in '{rules}'[/yellow]")
        raise typer.Exit(code=1)

    table = Table(title="Detection Rule Fixture Test Results", show_lines=True)
    table.add_column("Rule ID", style="bold cyan", width=10)
    table.add_column("Rule Name", width=35)
    table.add_column("Positive Test (should_fire)", justify="center", width=25)
    table.add_column("Negative Test (should_not_fire)", justify="center", width=25)

    all_passed = True

    for r in loaded:
        fire_path = Path(r.tests.should_fire)
        not_fire_path = Path(r.tests.should_not_fire)

        # 1. Positive test
        if not fire_path.is_file():
            pos_result = f"[red]MISSING FIXTURE ({fire_path})[/red]"
            all_passed = False
        else:
            fire_count = _run_rule_fixture(r, fire_path)
            if fire_count >= 1:
                pos_result = f"[green]PASS ({fire_count} alert)[/green]"
            else:
                pos_result = "[red]FAIL (0 alerts triggered)[/red]"
                all_passed = False

        # 2. Negative test
        if not not_fire_path.is_file():
            neg_result = f"[red]MISSING FIXTURE ({not_fire_path})[/red]"
            all_passed = False
        else:
            not_fire_count = _run_rule_fixture(r, not_fire_path)
            if not_fire_count == 0:
                neg_result = "[green]PASS (0 alerts)[/green]"
            else:
                neg_result = f"[red]FAIL ({not_fire_count} false positive alerts)[/red]"
                all_passed = False

        table.add_row(r.id, r.name, pos_result, neg_result)

    console.print(table)
    if not all_passed:
        console.print("\n[bold red]One or more rule tests failed.[/bold red]\n")
        raise typer.Exit(code=1)

    console.print(f"\n[bold green]All {len(loaded)} rules passed fixture testing![/bold green]\n")


@rules_app.command("show")
def rules_show(
    rule_id: str = typer.Argument(..., help="Unique Rule ID (e.g., SSH-001)."),
    rules: Path = typer.Option(Path("rules"), "--rules", "-r", help="Directory containing rules."),
) -> None:
    """Show details, logic, and MITRE mapping for a specific detection rule."""
    from sentinellog.rules.loader import load_rules_from_dir

    loaded = load_rules_from_dir(rules)
    matched = [r for r in loaded if r.id.upper() == rule_id.upper()]

    if not matched:
        console.print(f"[red]Error: Rule '{rule_id}' not found in '{rules}'[/red]")
        raise typer.Exit(code=1)

    r = matched[0]
    import yaml

    yaml_dump = yaml.dump(r.model_dump(), sort_keys=False)
    syntax = Syntax(yaml_dump, "yaml", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title=f"Rule Definition: {r.id} - {r.name}", border_style="cyan"))


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
