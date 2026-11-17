# SentinelLog Threat Model & Defensive Security Architecture

## 1. Overview & Trust Boundaries

Log processing systems occupy a sensitive operational position: they ingest untrusted, adversary-controllable input from edge servers, web applications, and network infrastructure, while running inside secure SOC networks or forensic analyst workstations.

```
       [ External Untrusted World ]
       Adversary generates malicious logs:
       - 10MB single-line payloads
       - Nested regex backtracking bombs
       - ANSI terminal escape injection
       - Path traversal in filenames
                    |
                    v
  ==== [ Trust Boundary 1: Ingestion ] ====
       SentinelLog Streaming Reader
       - 8,192 char line truncate/drop
       - Strip carriage return / control chars
                    |
                    v
  ==== [ Trust Boundary 2: Parsing & Regex ] ====
       Normalized Event Extraction
       - Atomic pre-compiled regexes
       - Bounded sliding window queues
                    |
                    v
  ==== [ Trust Boundary 3: Storage & Output ] ====
       Forensic SQLite Store & Visualizers
       - Parameterized SQL queries
       - HTML entity auto-escaping
       - Rich console safe rendering
```

---

## 2. Threat Analysis (STRIDE Matrix)

| Threat Category | Potential Attack Vector | Impact | SentinelLog Mitigation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker injects forged log lines with spoofed IP or timestamps | Misleading detection results or false alibis | Deduplication window preserves original evidence; ingestion records literal source line numbers; parser retains raw event string. |
| **Tampering** | Injected newline characters (`\n`, `\r`) creating phantom log records | Log forging / evasion | Streaming reader splits strictly on standard newline boundaries; raw line sanitization prevents control character execution. |
| **Repudiation** | Attacker clears audit logs or deletes files to hide activity | Inability to audit breach | Explicit detection rule `WIN-002` (Event 1102 / 104) alerts immediately on audit log clearance; forensic SQLite store persists historical records. |
| **Information Disclosure** | Leakage of sensitive credentials or internal IP topology to external servers | Privacy violation / recon | SentinelLog is **100% air-gapped** with zero outbound HTTP/DNS telemetry. Threat intel and GeoIP resolution occur strictly against local files. |
| **Denial of Service** | Extremely long lines or catastrophic regex backtracking (ReDoS) | CPU / Memory exhaustion crashing SOC ingestion | Hard **8,192-character safety cap** on every log line; linear non-backtracking regular expressions; stateful deques enforce maximum time windows and memory caps. |
| **Elevation of Privilege** | Exploiting log analysis tool to execute arbitrary commands or arbitrary file write | Complete analyst host compromise | Zero `eval()` or dynamic shell calls for log data; SQLite interactions use parameterized queries; report generators use Jinja2 with auto-escaping. |

---

## 3. Specific Defensive Implementations

### 3.1 Untrusted Input Sanitization (8,192-Character Cap)
Adversaries frequently attempt memory exhaustion attacks by sending multi-megabyte payloads in HTTP headers or syslog strings. In `src/sentinellog/ingest/reader.py`, the reader enforces:
```python
MAX_LINE_LENGTH = 8192
# Lines exceeding MAX_LINE_LENGTH are safely truncated to prevent buffer and memory bloat.
```

### 3.2 ReDoS Prevention (Regular Expression Denial of Service)
All detection rules in `rules/` and parsers in `parsers/` avoid nested quantifiers (e.g., `(a+)+`) and possess deterministic polynomial or linear matching characteristics. Rules are validated during `sentinellog doctor` and unit test runs.

### 3.3 ANSI Escape Injection Mitigation
Adversaries often attempt terminal control attacks (e.g., hiding lines or reprogramming terminal title bars) by injecting ANSI escape sequences into User-Agent or username fields. SentinelLog utilizes `rich` console styling which neutralizes raw terminal escape sequences during formatting.

### 3.4 Air-Gap Isolation Guarantee
In classified and high-security enterprise SOC environments, telemetry leakage is a critical threat. SentinelLog makes **zero outbound network connections**:
- GeoIP enrichment uses internal subnet maps.
- Threat intelligence uses local flat YAML/JSON files.
- The HTML report embeds all styling in pure CSS without any external Google Fonts, CDN links, or JavaScript.
- The Streamlit dashboard operates in headless offline mode.

### 3.5 Bounded Memory Footprint
Stateful detection engines (`threshold.py` and `sequence.py`) utilize `collections.deque` structures with automatic timestamp eviction. Event tracking entries older than the rule's sliding window (e.g., 60s or 120s) are automatically pruned on every new event, preventing memory growth over weeks of continuous operation.
