# SentinelLog — Offline-First SOC Threat Detection Platform

[![CI](https://github.com/sentinellog/sentinellog/actions/workflows/ci.yml/badge.svg)](https://github.com/sentinellog/sentinellog/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/downloads/)
[![Coverage](https://img.shields.io/badge/coverage-82.8%25-brightgreen.svg)](https://pytest.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](https://mypy-lang.org/)

**SentinelLog** is an offline-first Python log analysis and threat detection CLI platform engineered to mirror real-world Security Operations Center (SOC) analyst workflows. It streams multi-source logs, normalizes them against strict Pydantic v2 schemas, evaluates events through modular detection engines (match, threshold, sequence, anomaly, and threat intelligence), and presents actionable triage alerts in Rich terminal tables, self-contained HTML reports, and an interactive Streamlit operations dashboard.

---

## Key Capabilities

- **High-Throughput Streaming Ingestion**: Memory-bounded streaming reader handling plain text and `.gz` archives at **20,800 to 33,600+ events/second**.
- **Multi-Source Log Normalization**: Unified Pydantic v2 event schemas supporting:
  - Linux SSH Authentication & Sudo (`ssh_auth`)
  - Web Server Access Logs (Apache, Nginx, Caddy, CLF, JSON)
  - Windows Security Event Logs (EVTX/JSON) and Sysmon Operational Logs
  - RFC 3164 and RFC 5424 Syslog
- **Modular Multi-Paradigm Detection Engine**:
  - **Match**: Atomic signature matching with operators (`__in`, `__contains`, `__regex`, `__cidr`, `__gte`, `__lte`).
  - **Threshold**: Sliding-window event counts with distinct-entity tracking and cooldown suppression.
  - **Sequence**: Multi-stage ordered state machine detecting multi-step attacks (e.g. repeated brute force followed by successful login).
  - **Anomaly**: Rolling baseline Z-Score rate spike detection and off-hours administrative login tracking.
  - **Threat Intelligence**: Air-gapped IP/CIDR blocklist correlation.
- **Context & Risk Scoring**:
  - Deterministic composite risk score calculation (0–100) factoring severity, asset business criticality, and threat intel.
  - 10-minute sliding deduplication engine preventing alert fatigue.
  - Incident correlation engine grouping alerts by shared entities.
- **Analyst Interfaces**:
  - **Rich Terminal CLI**: Beautiful colored alerts, incident summaries, and diagnostic tables.
  - **Air-Gapped HTML Report**: 100% self-contained, responsive executive report with embedded pure CSS (zero external CDNs or scripts).
  - **Interactive Streamlit SOC Dashboard**: 4 dedicated tabs for Incident Triage, Threat Hunting, MITRE Matrix coverage, and Rules Catalog.
- **Defensive Safeguards**: Built-in 8,192-character line truncation, ANSI escape neutralization, ReDoS prevention, and parameterized SQLite storage.

---

## Installation

### Prerequisites
- Python 3.11 or higher
- Git

### Setup
```powershell
# Clone or navigate to the project directory
cd "D:\Adnan project\Sentinallog"

# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# Install SentinelLog with dev and dashboard dependencies
pip install -e ".[dev,dashboard]"
```

---

## CLI Command Catalog

| Command | Subcommand | Description |
| :--- | :--- | :--- |
| `sentinellog doctor` | — | Comprehensive system diagnostic (runtime, config, rules, intel, SQLite read/write, disk space). |
| `sentinellog scan` | — | Stream logs through detection engine, score risks, correlate incidents, and store in SQLite. |
| `sentinellog tail` | — | Real-time continuous log follower with automatic rotation and truncation handling. |
| `sentinellog stats` | — | Rapidly parse and display event statistics and breakdowns without running detection rules. |
| `sentinellog rules` | `list` | Display full catalog of loaded detection rules, MITRE techniques, and severities. |
| `sentinellog rules` | `test` | Validate rules against test vectors and syntax integrity. |
| `sentinellog alerts` | `list` | Query and filter generated security alerts from the SQLite store. |
| `sentinellog alerts` | `mark` | Update triage status (`open`, `investigating`, `resolved`, `false_positive`) for an alert. |
| `sentinellog incidents`| `list` | View correlated security incidents aggregated across multiple alerts. |
| `sentinellog simulate`| — | Generate synthetic benign logs alongside labeled attack scenarios with `labels.json`. |
| `sentinellog evaluate`| — | Evaluate detection precision, recall, and F1-score against ground-truth benchmark labels. |
| `sentinellog report` | — | Export an executive, air-gapped forensic HTML report with pure CSS. |
| `sentinellog dashboard`| — | Launch the interactive Streamlit SOC analyst operations console. |

---

## Quick-Start Operational Walkthrough

### 1. Verify System Health
```powershell
sentinellog doctor
```

### 2. Generate Realistic Attack Scenarios
```powershell
sentinellog simulate --scenario multi --out-dir logs/synthetic --lines 5000
```

### 3. Scan and Detect
```powershell
sentinellog scan logs/synthetic --rules rules --db sentinellog.db
```

### 4. Evaluate Detection Accuracy
```powershell
sentinellog evaluate --alerts-db sentinellog.db --labels logs/synthetic/labels.json
```

### 5. Generate Executive HTML Report
```powershell
sentinellog report --db sentinellog.db --out report.html
```

### 6. Launch the Interactive SOC Dashboard
```powershell
sentinellog dashboard --db sentinellog.db --port 8501
```

---

## Performance Benchmark

SentinelLog delivers production-grade log ingestion and detection throughput:
- **Throughput**: **20,842 to 33,660 events/second**
- **Latency**: 100,000 log lines processed in **4.80 seconds**
- **Memory Footprint**: Bounded sliding deques with automatic timestamp-based eviction preventing memory leaks.

To run the performance benchmark:
```powershell
pytest tests/performance -m slow -s --no-cov
```

---

## Testing & Quality Gates

Run full test suite with coverage:
```powershell
pytest -q
```
*Current test suite: 88 passing tests, 82.80% coverage.*

Run static linters and type checkers:
```powershell
ruff check .
ruff format --check .
mypy src
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
