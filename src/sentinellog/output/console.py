"""Rich terminal console formatting and alert detail rendering."""

from collections import Counter
from collections.abc import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinellog.models import Alert

console = Console()

SEVERITY_COLORS = {
    "info": "blue",
    "low": "cyan",
    "medium": "yellow",
    "high": "bold red",
    "critical": "bold white on red",
}


def render_alerts_table(alerts: Sequence[Alert]) -> None:
    """Render a styled Rich table of security alerts."""
    if not alerts:
        console.print("[bold green]Scan completed. No security alerts triggered.[/bold green]\n")
        return

    table = Table(title="Detected Security Alerts", show_lines=True)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Score", justify="right", width=7)
    table.add_column("Rule ID", style="bold", width=10)
    table.add_column("Rule Name", width=30)
    table.add_column("Entities", width=25)
    table.add_column("Count", justify="right", width=7)
    table.add_column("First Seen", style="dim", width=20)
    table.add_column("Last Seen", style="dim", width=20)

    for alert in alerts:
        sev_str = alert.severity.value.upper()
        color = SEVERITY_COLORS.get(alert.severity.value, "white")
        styled_sev = f"[{color}]{sev_str}[/{color}]"

        # Format entities summary
        entity_parts = []
        for k, v in alert.entities.items():
            vals = ", ".join(v[:2])
            if len(v) > 2:
                vals += f" (+{len(v) - 2})"
            entity_parts.append(f"{k}: {vals}")
        entities_str = "\n".join(entity_parts) or "-"

        first_str = alert.first_seen.strftime("%Y-%m-%d %H:%M:%S")
        last_str = alert.last_seen.strftime("%Y-%m-%d %H:%M:%S")

        table.add_row(
            styled_sev,
            str(alert.score),
            alert.rule_id,
            alert.rule_name,
            entities_str,
            str(alert.count),
            first_str,
            last_str,
        )

    console.print(table)


def render_alert_details(alerts: Sequence[Alert], limit: int = 5) -> None:
    """Render expandable detail panels with raw evidence lines for the top alerts."""
    top_alerts = sorted(alerts, key=lambda a: (a.score, a.count), reverse=True)[:limit]
    for idx, alert in enumerate(top_alerts, 1):
        color = SEVERITY_COLORS.get(alert.severity.value, "white")
        title = f"[bold {color}]Alert #{idx}: [{alert.rule_id}] {alert.rule_name}[/bold {color}]"

        evidence_lines = []
        for ev in alert.evidence[:5]:
            evidence_lines.append(f"  [dim]{ev.file}:{ev.line_number}[/dim] -> {ev.raw}")
        if len(alert.evidence) > 5:
            evidence_lines.append(f"  [dim]... and {len(alert.evidence) - 5} more lines[/dim]")

        tactic = alert.mitre.get("tactic", "N/A")
        technique = alert.mitre.get("technique", "N/A")
        content = (
            f"[bold]Explanation:[/bold] {alert.explanation}\n"
            f"[bold]MITRE ATT&CK:[/bold] {tactic} - {technique}\n"
            f"[bold]Action:[/bold] {alert.recommended_action}\n"
            f"[bold]Raw Evidence Sample:[/bold]\n" + "\n".join(evidence_lines)
        )

        console.print(Panel(content, title=title, border_style=color.split()[-1]))


def render_scan_summary(
    events_parsed: int,
    bad_lines: int,
    rules_loaded: int,
    alerts: Sequence[Alert],
    runtime_seconds: float,
) -> None:
    """Render executive summary footer showing scan metrics and throughput."""
    sev_counts = Counter(a.severity.value for a in alerts)
    eps = (events_parsed / runtime_seconds) if runtime_seconds > 0 else 0.0

    summary_table = Table(title="Scan Execution Summary", show_lines=True)
    summary_table.add_column("Metric", style="bold cyan", width=25)
    summary_table.add_column("Value", justify="right", width=15)

    summary_table.add_row("Events Parsed", f"{events_parsed:,}")
    summary_table.add_row("Bad / Corrupt Lines", f"{bad_lines:,}")
    summary_table.add_row("Rules Evaluated", str(rules_loaded))
    summary_table.add_row("Total Alerts Triggered", f"{len(alerts):,}")

    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev_counts[sev] > 0:
            color = SEVERITY_COLORS.get(sev, "white")
            summary_table.add_row(
                f"  [{color}]{sev.upper()}[/{color}] Alerts",
                f"[{color}]{sev_counts[sev]}[/{color}]",
            )

    summary_table.add_row("Execution Runtime", f"{runtime_seconds:.2f} s")
    summary_table.add_row("Throughput", f"{eps:,.1f} events/s")

    console.print(summary_table)
