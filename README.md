# SentinelLog

**SentinelLog** is an offline-first Python log analysis and threat detection CLI platform engineered to mirror real-world Security Operations Center (SOC) analyst workflows. It streams multi-source logs, normalizes them against strict Pydantic v2 schemas, evaluates events through modular detection engines (match, threshold, sequence, anomaly, and threat intelligence), and presents actionable triage alerts in Rich terminal tables, self-contained HTML reports, and interactive dashboards.

---

## Key Capabilities

- **Streaming Multi-Source Ingestion**: Memory-bounded streaming reader handling plain text and gzip archives (`.gz`), with heuristic parser auto-detection.
- **Normalized Event Schema**: Strict Pydantic v2 models normalizing SSH authentication, Apache/Nginx web access, Windows Event Logs, and Syslog into unified security events.
- **Tiered Threat Detection Engine**:
  - **Match**: Single-event atomic signature matching with rich operators (`__in`, `__contains`, `__icontains`, `__regex`, `__cidr`, `__gte`, `__lte`, `__exists`).
  - **Threshold**: Sliding time-window event counts with distinct-entity tracking (e.g. password spraying across $\ge 8$ distinct users) and cooldown suppression.
  - **Timestamp Reorder Buffer**: Micro-batch reordering buffer to handle slightly out-of-order log records.
- **Realistic Attack Simulator**: Generates background benign traffic alongside labeled attack scenarios (`brute_force`, `spraying`, `web_attack`, `windows_compromise`, `mixed`) with ground-truth `labels.json`.
- **Automated Validation Metrics**: Evaluates **scenario recall** and **alert precision** against labeled benchmark datasets.
- **Defensive Safeguards**: Built-in 8,192-char line truncation, ANSI escape code stripping, ReDoS prevention (nested quantifier rejection), and safe YAML deserialization.

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

# Install dependencies in development mode
.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

---

## Quick Start Walkthrough

### 1. Inspect Rule Catalog
```powershell
sentinellog rules list
```
```text
                      Detection Rules Catalog (11 rules)                       
┌──────────┬──────────────────────────────┬──────────┬───────────┬────────────┬───────────────────────────┬─────────┐
│ Rule ID  │ Rule Name                    │ Severity │ Type      │ Log Source │ MITRE ATT&CK              │ Status  │
├──────────┼──────────────────────────────┼──────────┼───────────┼────────────┼───────────────────────────┼─────────┤
│ SSH-001  │ SSH brute force from a       │   HIGH   │ threshold │ ssh_auth   │ T1110.001 (Credential     │ ENABLED │
│          │ single source                │          │           │            │ Access)                   │         │
│ SSH-002  │ SSH password spraying across │   HIGH   │ threshold │ ssh_auth   │ T1110.003 (Credential     │ ENABLED │
│          │ distinct accounts            │          │           │            │ Access)                   │         │
│ SSH-004  │ Direct root SSH login        │  MEDIUM  │ match     │ ssh_auth   │ T1078.001 (Initial        │ ENABLED │
│          │ attempt                      │          │           │            │ Access)                   │         │
│ SSH-005  │ Enumeration of invalid SSH   │  MEDIUM  │ threshold │ ssh_auth   │ T1087.001 (Discovery)     │ ENABLED │
│          │ usernames                    │          │           │            │                           │         │
│ SSH-007  │ Sudo execution of            │   HIGH   │ match     │ ssh_auth   │ T1548.003 (Privilege      │ ENABLED │
│          │ interactive shell or editor  │          │           │            │ Escalation)               │         │
│ WEB-001  │ SQL injection attempt in URL │   HIGH   │ match     │ web_access │ T1190 (Initial Access)    │ ENABLED │
│ WEB-002  │ Path traversal directory     │   HIGH   │ match     │ web_access │ T1190 (Initial Access)    │ ENABLED │
│          │ climbing in URL              │          │           │            │                           │         │
│ WEB-003  │ Automated vulnerability      │  MEDIUM  │ match     │ web_access │ T1595.002                 │ ENABLED │
│          │ scanner user agent           │          │           │            │ (Reconnaissance)          │         │
│ WEB-004  │ High rate of HTTP 404 Not    │  MEDIUM  │ threshold │ web_access │ T1083 (Discovery)         │ ENABLED │
│          │ Found responses              │          │           │            │                           │         │
│ WEB-006  │ Probing for sensitive        │   HIGH   │ match     │ web_access │ T1083 (Discovery)         │ ENABLED │
│          │ configuration files          │          │           │            │                           │         │
│ WEB-007  │ Remote command execution     │ CRITICAL │ match     │ web_access │ T1059.004 (Execution)     │ ENABLED │
│          │ probe in URL parameter       │          │           │            │                           │         │
└──────────┴──────────────────────────────┴──────────┴───────────┴────────────┴───────────────────────────┴─────────┘
```

### 2. Verify Rules against Test Fixtures
```powershell
sentinellog rules test
```
```text
All 11 rules passed fixture testing!
```

### 3. Generate Synthetic Benchmark Logs
```powershell
sentinellog simulate --scenario mixed --out data/generated --seed 42
```

### 4. Scan Logs and Generate Triage Output
```powershell
sentinellog scan data/generated --rules rules/ --out data/generated/report.json
```
```text
            Scan Execution Summary             
┌───────────────────────────┬─────────────────┐
│ Metric                    │           Value │
├───────────────────────────┼─────────────────┤
│ Events Parsed             │          10,220 │
├───────────────────────────┼─────────────────┤
│ Bad / Corrupt Lines       │               0 │
├───────────────────────────┼─────────────────┤
│ Rules Evaluated           │              11 │
├───────────────────────────┼─────────────────┤
│ Total Alerts Triggered    │              53 │
├───────────────────────────┼─────────────────┤
│   CRITICAL Alerts         │               1 │
├───────────────────────────┼─────────────────┤
│   HIGH Alerts             │               7 │
├───────────────────────────┼─────────────────┤
│   MEDIUM Alerts           │              45 │
├───────────────────────────┼─────────────────┤
│ Execution Runtime         │          1.45 s │
├───────────────────────────┼─────────────────┤
│ Throughput                │ 7,039.6 ev/s    │
└───────────────────────────┴─────────────────┘
Exported alerts to data\generated\report.json
```

### 5. Benchmark Detection Precision & Recall
```powershell
sentinellog stats data/generated
```
```text
                  Detection Accuracy Benchmark (Ground Truth)                  
┌───────────────────────────┬─────────────────┬───────────────────────────────┐
│ Benchmark Metric          │           Score │ Notes                         │
├───────────────────────────┼─────────────────┼───────────────────────────────┤
│ Scenario Recall           │          100.0% │ 3/3 scenarios fully detected  │
├───────────────────────────┼─────────────────┼───────────────────────────────┤
│ Alert Precision           │          100.0% │ 53/53 alerts match labeled    │
│                           │                 │ attack lines                  │
└───────────────────────────┴─────────────────┴───────────────────────────────┘
```

---

## Testing & Quality Assurance

SentinelLog enforces strict code quality gates:
```powershell
# Run Ruff linter
.venv\Scripts\python.exe -m ruff check .

# Run Ruff code formatter verification
.venv\Scripts\python.exe -m ruff format --check .

# Run Mypy static type checker (strict mode)
.venv\Scripts\python.exe -m mypy src

# Run test suite with 80% minimum coverage gate
.venv\Scripts\python.exe -m pytest -q
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](file:///D:/Adnan%20project/Sentinallog/LICENSE) file for details.
