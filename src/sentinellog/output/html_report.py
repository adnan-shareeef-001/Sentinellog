"""Self-contained HTML executive report generator with embedded styles and analytics."""

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Template

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ company_name }} - Security Executive Report</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --green: #22c55e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
      line-height: 1.5;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }
    h1 { font-size: 1.875rem; font-weight: 700; color: var(--text-main); }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.6rem;
      font-size: 0.75rem;
      font-weight: 600;
      border-radius: 9999px;
      text-transform: uppercase;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    .badge-medium { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
    
    .grid-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 1.25rem;
    }
    .card-title { font-size: 0.875rem; color: var(--text-muted); font-weight: 500; text-transform: uppercase; }
    .card-value { font-size: 2rem; font-weight: 700; margin-top: 0.5rem; color: var(--text-main); }
    .card-note { font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem; }

    section { margin-bottom: 2.5rem; }
    h2 { font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
    
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border-radius: 0.5rem;
      overflow: hidden;
      border: 1px solid var(--border);
    }
    th, td {
      padding: 0.75rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
      font-size: 0.875rem;
    }
    th { background: rgba(0, 0, 0, 0.2); color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }

    .bar-container {
      background: rgba(255, 255, 255, 0.05);
      border-radius: 4px;
      overflow: hidden;
      height: 12px;
      display: flex;
      margin: 1rem 0;
    }
    .bar-crit { background: var(--critical); }
    .bar-high { background: var(--high); }
    .bar-med { background: var(--medium); }
    .bar-low { background: var(--low); }

    .code-box {
      background: rgba(0, 0, 0, 0.3);
      padding: 0.5rem;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.75rem;
      color: #cbd5e1;
      max-height: 120px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    footer {
      border-top: 1px solid var(--border);
      padding-top: 1.5rem;
      text-align: center;
      font-size: 0.75rem;
      color: var(--text-muted);
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>{{ company_name }}</h1>
        <p style="color: var(--text-muted); font-size: 0.875rem;">Executive Security Threat Analysis & Incident Report</p>
      </div>
      <div style="text-align: right;">
        <p style="font-size: 0.875rem; color: var(--text-muted);">Generated: <strong>{{ generated_at }}</strong></p>
        <p style="font-size: 0.75rem; color: var(--text-muted);">Reporting Window: <strong>{{ window }}</strong></p>
      </div>
    </header>

    <div class="grid-cards">
      <div class="card">
        <div class="card-title">Total Alerts Triggered</div>
        <div class="card-value">{{ total_alerts }}</div>
        <div class="card-note">{{ critical_count }} Critical, {{ high_count }} High</div>
      </div>
      <div class="card">
        <div class="card-title">Correlated Incidents</div>
        <div class="card-value">{{ total_incidents }}</div>
        <div class="card-note">Multi-vector threat clusters</div>
      </div>
      <div class="card">
        <div class="card-title">Peak Risk Score</div>
        <div class="card-value" style="color: {% if max_score >= 80 %}var(--critical){% elif max_score >= 50 %}var(--high){% else %}var(--green){% endif %};">{{ max_score }} / 100</div>
        <div class="card-note">Composite severity weighting</div>
      </div>
      <div class="card">
        <div class="card-title">Threat Intel Hits</div>
        <div class="card-value">{{ threat_intel_hits }}</div>
        <div class="card-note">Malicious indicators blocked</div>
      </div>
    </div>

    <section>
      <h2>Alert Severity Distribution</h2>
      <div class="bar-container">
        {% if total_alerts > 0 %}
          <div class="bar-crit" style="width: {{ (critical_count / total_alerts * 100)|round(1) }}%;"></div>
          <div class="bar-high" style="width: {{ (high_count / total_alerts * 100)|round(1) }}%;"></div>
          <div class="bar-med" style="width: {{ (med_count / total_alerts * 100)|round(1) }}%;"></div>
          <div class="bar-low" style="width: {{ (low_count / total_alerts * 100)|round(1) }}%;"></div>
        {% endif %}
      </div>
      <div style="display: flex; gap: 1.5rem; font-size: 0.875rem;">
        <span><span class="badge badge-critical">Critical</span> {{ critical_count }}</span>
        <span><span class="badge badge-high">High</span> {{ high_count }}</span>
        <span><span class="badge badge-medium">Medium</span> {{ med_count }}</span>
        <span><span class="badge badge-low">Low</span> {{ low_count }}</span>
      </div>
    </section>

    {% if incidents %}
    <section>
      <h2>Correlated Security Incidents</h2>
      <table>
        <thead>
          <tr>
            <th>Incident ID</th>
            <th>Title</th>
            <th>Severity</th>
            <th>Score</th>
            <th>Status</th>
            <th>Alerts</th>
            <th>Target / Source</th>
            <th>Timeline</th>
          </tr>
        </thead>
        <tbody>
          {% for inc in incidents %}
          <tr>
            <td style="font-family: monospace; color: var(--accent);">{{ inc.id }}</td>
            <td><strong>{{ inc.title }}</strong></td>
            <td><span class="badge badge-{{ inc.severity }}">{{ inc.severity }}</span></td>
            <td><strong>{{ inc.score }}</strong></td>
            <td><span style="text-transform: uppercase; font-size: 0.75rem;">{{ inc.status }}</span></td>
            <td>{{ inc.alert_count }}</td>
            <td><code>{{ inc.primary_entity }}</code></td>
            <td style="color: var(--text-muted); font-size: 0.75rem;">{{ inc.first_seen[:19] }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
    {% endif %}

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem;">
      <section>
        <h2>Top Attacking IP Addresses</h2>
        <table>
          <thead>
            <tr><th>Source IP</th><th>Alerts</th></tr>
          </thead>
          <tbody>
            {% for ip, count in top_ips %}
            <tr><td style="font-family: monospace;">{{ ip }}</td><td><strong>{{ count }}</strong></td></tr>
            {% else %}
            <tr><td colspan="2" style="color: var(--text-muted);">No external IP addresses observed</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </section>

      <section>
        <h2>Top Targeted Accounts</h2>
        <table>
          <thead>
            <tr><th>Target User</th><th>Alerts</th></tr>
          </thead>
          <tbody>
            {% for user, count in top_users %}
            <tr><td style="font-family: monospace;">{{ user }}</td><td><strong>{{ count }}</strong></td></tr>
            {% else %}
            <tr><td colspan="2" style="color: var(--text-muted);">No target users recorded</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </section>
    </div>

    <section>
      <h2>MITRE ATT&CK® Coverage Breakdown</h2>
      <table>
        <thead>
          <tr>
            <th>Tactic</th>
            <th>Technique ID</th>
            <th>Trigger Count</th>
          </tr>
        </thead>
        <tbody>
          {% for tactic, tech, count in mitre_items %}
          <tr>
            <td><strong>{{ tactic }}</strong></td>
            <td><code>{{ tech }}</code></td>
            <td>{{ count }}</td>
          </tr>
          {% else %}
          <tr><td colspan="3" style="color: var(--text-muted);">No MITRE ATT&CK techniques mapped</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </section>

    {% if alerts %}
    <section>
      <h2>Recent Security Alerts (Top {{ [alerts|length, 25]|min }})</h2>
      <table>
        <thead>
          <tr>
            <th>Rule ID & Name</th>
            <th>Severity</th>
            <th>Entities</th>
            <th>Recommended SOC Action</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {% for a in alerts[:25] %}
          <tr>
            <td>
              <code>{{ a.rule_id }}</code><br>
              <strong>{{ a.rule_name }}</strong>
            </td>
            <td><span class="badge badge-{{ a.severity }}">{{ a.severity }}</span></td>
            <td style="font-size: 0.75rem;">
              {% for k, vals in a.entities.items() %}
                <strong>{{ k }}:</strong> {{ vals|join(', ') }}<br>
              {% endfor %}
            </td>
            <td style="font-size: 0.8rem; color: #cbd5e1;">{{ a.recommended_action }}</td>
            <td style="font-size: 0.75rem; color: var(--text-muted);">{{ a.first_seen[:19] }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
    {% endif %}

    <footer>
      Generated by <strong>SentinelLog</strong> — Offensive-Defense SOC Telemetry & Detection Engine
    </footer>
  </div>
</body>
</html>
"""


def generate_html_report(
    alerts: list[dict[str, Any]],
    incidents: list[dict[str, Any]] | None = None,
    output_path: Path | str = "report.html",
    company_name: str = "SentinelLog SOC Operations",
    window: str = "Last 24 Hours",
) -> Path:
    """Render self-contained HTML executive report from alerts and incident records."""
    incidents_list = incidents or []

    # Calculate statistics
    total_alerts = len(alerts)
    total_incidents = len(incidents_list)

    sev_counts = Counter(str(a.get("severity", "low")).lower() for a in alerts)
    critical_count = sev_counts.get("critical", 0)
    high_count = sev_counts.get("high", 0)
    med_count = sev_counts.get("medium", 0)
    low_count = sev_counts.get("low", 0)

    max_score = max((int(a.get("score", 0)) for a in alerts), default=0)

    ti_hits = sum(1 for a in alerts if a.get("rule_id") == "GEN-001" or a.get("score", 0) >= 95)

    # Top IP entities
    ip_counter: Counter[str] = Counter()
    user_counter: Counter[str] = Counter()
    mitre_counter: Counter[tuple[str, str]] = Counter()

    for a in alerts:
        entities = a.get("entities", {})
        for ip in entities.get("src_ip", []):
            ip_counter[str(ip)] += 1
        for u in entities.get("user", []):
            user_counter[str(u)] += 1

        mitre = a.get("mitre", {})
        tactic = mitre.get("tactic") or "Unknown"
        tech = mitre.get("technique") or "Unknown"
        if tactic != "Unknown" or tech != "Unknown":
            mitre_counter[(tactic, tech)] += 1

    top_ips = ip_counter.most_common(5)
    top_users = user_counter.most_common(5)
    mitre_items = [
        (tactic, tech, count)
        for (tactic, tech), count in sorted(mitre_counter.items(), key=lambda x: x[1], reverse=True)
    ]

    template = Template(HTML_REPORT_TEMPLATE)
    rendered_html = template.render(
        company_name=company_name,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        window=window,
        total_alerts=total_alerts,
        total_incidents=total_incidents,
        critical_count=critical_count,
        high_count=high_count,
        med_count=med_count,
        low_count=low_count,
        max_score=max_score,
        threat_intel_hits=ti_hits,
        incidents=incidents_list,
        alerts=alerts,
        top_ips=top_ips,
        top_users=top_users,
        mitre_items=mitre_items,
    )

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(rendered_html, encoding="utf-8")
    return out_file
