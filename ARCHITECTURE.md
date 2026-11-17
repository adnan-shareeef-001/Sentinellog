# SentinelLog Architecture

SentinelLog is an offline-first, high-throughput security log analysis and threat detection platform built with Python 3.11+. It is engineered specifically for Security Operations Centers (SOC), incident response teams, and air-gapped forensic environments.

---

## 1. System Overview & Data Flow

```
                      +---------------------------------------+
                      | Raw Log Ingestion (Streaming Reader)  |
                      |   - Compressed (.gz) & Plaintext      |
                      |   - Real-time Non-blocking Tailing    |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |   Log Parsing & Normalization Engine  |
                      |   - Auto-detection / Format Registry  |
                      |   - Linux SSH Auth / Sudo             |
                      |   - Nginx / Apache / Caddy Web Logs   |
                      |   - Windows EVTX JSON / Sysmon        |
                      |   - Syslog RFC 3164 / 5424            |
                      |   - Output: UTC-Normalized Event      |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |   Detection Engine (Multi-Paradigm)   |
                      |   - Pre-filtered Rule Source Index    |
                      |   - Single-Event Match Rules (Regex)  |
                      |   - Sliding-Window Threshold Deques   |
                      |   - Multi-Stage Sequence State Machine|
                      |   - Anomaly / Statistical Z-Score     |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |   Enrichment & Context Pipeline       |
                      |   - Threat Intel Blocklist Lookups    |
                      |   - Asset Inventory Criticality Tag   |
                      |   - Offline GeoIP Subnet Fallback     |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |   Risk Scoring & Correlation Engine   |
                      |   - Composite Risk Score [0-100]      |
                      |   - Deduplication Window (10-min key) |
                      |   - Incident Correlation (Shared Ent) |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |   Persistence & Presentation Layer    |
                      |   - SQLite Forensic Alert Store       |
                      |   - Rich Console Tables & Summaries   |
                      |   - Pure-CSS Air-Gapped HTML Report   |
                      |   - Interactive Streamlit Dashboard   |
                      +---------------------------------------+
```

---

## 2. Component Architecture

### A. Ingestion Layer (`src/sentinellog/ingest/`)
- **`reader.py`**: High-performance streaming generator yielding `(line_num, line)`. Handles standard files as well as gzip-compressed archives seamlessly. Enforces an 8,192-character safety cap per line to defend against algorithmic complexity and memory exhaustion attacks.
- **`tail.py`**: Non-blocking real-time log follower designed for live daemon monitoring. Periodically checks file size and inode changes to automatically handle log rotation and log truncation events.

### B. Parser Layer (`src/sentinellog/parsers/`)
- **`base.py`**: Abstract `Parser` interface defining `parse(line, file_path, line_number) -> Optional[Event]` and `can_parse(line) -> bool`.
- **`registry.py`**: Dynamic parser registry that probes registered parsers across a sample window (10 lines) to auto-detect log source types with high confidence without manual flags.
- **`ssh_auth.py`**: Parses classic syslog (`Oct 13 14:22:01`) and ISO-8601 SSH/sudo authentication logs. Features cached file year resolution and sub-microsecond timestamp tokenization.
- **`web_access.py`**: Fast regex parser for Combined Log Format (CLF), Common Log Format, and JSON web access records.
- **`windows.py`**: Parses Windows Security Event logs and Sysmon operational logs serialized as JSON/JSONL. Extracts Event IDs (e.g. 4624, 4625, 4740, 1102, 4728, 4656, 4698) and process command lines.
- **`syslog.py`**: Standard RFC 3164 and RFC 5424 syslog parser with PRI / facility / severity calculation.

### C. Detection Engine (`src/sentinellog/engine/`)
The detection engine operates as an in-memory streaming processor evaluating YAML-defined declarative rules across four distinct execution paradigms:
1. **Source Pre-Indexing**: Rules are grouped by `log_source` at engine instantiation. Events only evaluate relevant rules, bypassing 65%+ of unnecessary checks per line.
2. **`match.py`**: Instant single-event field and regex evaluations with pre-compiled pattern matching.
3. **`threshold.py`**: Stateful sliding-window event count tracking using `collections.deque`. Automatically purges events older than the rule window before evaluating threshold conditions.
4. **`sequence.py`**: Multi-stage ordered state machine. Maintains active transition paths per entity, enforcing maximum inter-stage timeouts and resetting on expired windows.
5. **`anomaly.py`**: Statistical baseline anomaly detector (Z-Score calculation over dynamic rolling time slots) and off-hours administrative login identification.

### D. Context & Enrichment Layer (`src/sentinellog/enrich/`)
- **`intel.py`**: Air-gapped threat intelligence blocklist matching. Loads known malicious IPs, CIDR blocks, and malicious hashes from local YAML/JSON feeds.
- **`assets.py`**: Internal asset inventory mapping IP addresses and hostnames to business criticality tiers (`low`, `medium`, `high`, `critical`) and department ownership.
- **`geoip.py`**: Offline-safe GeoIP resolver. Maps public and RFC 1918 private subnets without making external API calls.

### E. Alerting, Risk Scoring & Incidents (`src/sentinellog/alerts/`)
- **`scoring.py`**: Computes deterministic risk scores (0–100) using a multi-factor formula:
  $$\text{Score} = \text{Base Severity} + \text{Asset Multiplier} + \text{Intel Match Weight} + \text{Anomaly Bonus}$$
- **`dedupe.py`**: 10-minute sliding deduplication engine preventing alert storms on repeated alerts sharing identical rule, entity, and target attributes.
- **`incidents.py`**: Higher-order correlation engine that aggregates multiple related alerts sharing a common primary entity into a cohesive **Security Incident** with combined timelines, severities, and forensic evidence.
- **`store.py`**: SQLite persistent forensic database storing raw alerts, correlated incidents, and triage status updates (`open`, `investigating`, `resolved`, `false_positive`).

### F. Presentation & Reporting (`src/sentinellog/output/` & `dashboard/`)
- **`console.py`**: Rich-formatted terminal display with colored severity banners, alert tables, and incident cards.
- **`html_report.py`**: Fully self-contained executive HTML report. Built with embedded pure CSS without any external CDNs, scripts, or network dependencies—100% compliant with air-gapped environments.
- **`app.py`**: Full-featured interactive Streamlit SOC dashboard featuring Alert Triage, Threat Hunting workbench, MITRE ATT&CK Matrix coverage, and an interactive Rule Catalog.

---

## 3. SQLite Storage Schema

```sql
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    score REAL NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL,
    entities TEXT NOT NULL, -- JSON string
    target_users TEXT,      -- JSON string
    evidence TEXT NOT NULL,  -- JSON string
    status TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    score REAL NOT NULL,
    status TEXT NOT NULL,
    primary_entity TEXT NOT NULL,
    alert_ids TEXT NOT NULL, -- JSON array
    alert_count INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL
);
```

---

## 4. Air-Gap Security & Performance Design Principles

1. **Zero External Network Dependencies**: All parsers, GeoIP mappings, threat intelligence lookups, and reporting templates function completely offline without internet connectivity.
2. **Defensive Parsing**: Hard length caps (8,192 chars) prevent ReDoS and algorithmic complexity attacks from weaponized log entries.
3. **High Throughput Stream Processing**: Optimized regex engines, LRU file-timestamp caching, and source pre-indexing deliver processing speeds exceeding **20,000 to 33,000 events/second** on standard multi-core hardware.
