# Threat Model for SentinelLog

A defensive security tool is itself a high-value target for adversaries. If an attacker can crash the monitoring engine or execute code through a crafted log line, they effectively blind the SOC. This threat model identifies attack vectors against SentinelLog and documents defensive mitigations.

---

## 1. Attack Vectors & Mitigations

### 1.1 Log Injection (Log Forgery)
* **Threat:** An adversary sends HTTP requests containing newline characters (`\r\n`) or ANSI escape sequences in headers (e.g., `User-Agent: Mozilla\nAccepted password for root`). If unhandled, this could forge artificial events or corrupt the terminal.
* **Mitigation:**
  - Strict line-by-line streaming: newlines act as physical delimiters.
  - ANSI strip/escape: raw strings are sanitized before console or HTML rendering.
  - Provenance tracking: line numbers are tied strictly to file byte offsets.

### 1.2 Resource Exhaustion / Denial of Service
* **Threat:** An attacker sends a 500 MB single-line payload or triggers thousands of events to exhaust RAM.
* **Mitigation:**
  - Cap maximum line length at 4096 bytes (`max_line_length`). Longer lines are truncated safely with a recorded parsing warning.
  - Streaming readers use Python generators; memory consumption remains $O(1)$ relative to total log file size.

### 1.3 Regular Expression Denial of Service (ReDoS)
* **Threat:** Crafting malicious log payloads designed to trigger catastrophic backtracking in detection or parser regexes.
* **Mitigation:**
  - Avoid nested quantifiers (e.g., `(a+)+$`).
  - Standardized benchmarks and linting of regular expressions.

### 1.4 HTML Report Cross-Site Scripting (XSS)
* **Threat:** An attacker puts `<script>alert(1)</script>` in a User-Agent or URL, which then executes in the security analyst's browser when opening the HTML incident report.
* **Mitigation:**
  - Jinja2 templates configure `autoescape=True` by default. All evidence strings are HTML-entity-encoded prior to rendering.

### 1.5 Malicious YAML Rules
* **Threat:** An attacker compromises a rule repository and includes Python object deserialization payloads in a rule file.
* **Mitigation:**
  - Exclusively use `yaml.safe_load()`.
  - Validate all rules against rigid Pydantic schemas before registration.
