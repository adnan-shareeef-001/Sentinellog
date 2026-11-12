# SentinelLog Data Model Specification

## 1. Normalized `Event` Model
Every raw log line is transformed into a standardized `Event` schema:

| Field | Type | Description |
|---|---|---|
| `timestamp` | `datetime` | Timezone-aware UTC timestamp. |
| `source_type` | `str` | Log source category (`ssh_auth`, `web_access`, `windows_security`, `syslog`). |
| `host` | `str` | Hostname or machine name. |
| `event_type` | `str` | Normalized action (`auth_failure`, `auth_success`, `http_request`, `user_created`, `log_cleared`, `process_created`). |
| `user` | `Optional[str]` | Username or account involved. |
| `src_ip` | `Optional[str]` | Originating IP address (IPv4 or IPv6). |
| `dst_ip` | `Optional[str]` | Destination IP address. |
| `src_port` | `Optional[int]` | Originating network port. |
| `http_method` | `Optional[str]` | HTTP verb (GET, POST, PUT, DELETE, etc.). |
| `url` | `Optional[str]` | Requested URL path and query string. |
| `status_code` | `Optional[int]` | HTTP response status code (e.g., 200, 404, 500). |
| `user_agent` | `Optional[str]` | HTTP client User-Agent header. |
| `bytes` | `Optional[int]` | Response byte count. |
| `process` | `Optional[str]` | Executable name or binary path. |
| `command_line` | `Optional[str]` | Complete process command-line invocation. |
| `event_id` | `Optional[int]` | Native Windows event identifier (e.g., 4625). |
| `raw` | `str` | Original line text (capped at 4096 chars). |
| `line_number` | `int` | 1-based line number in source file. |
| `file` | `str` | Absolute path of source log file. |
| `parse_confidence`| `float` | Quality rating from 0.0 to 1.0. |

## 2. `Alert` Model
An `Alert` represents detection rule satisfaction:

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Unique UUIDv4 identifier. |
| `rule_id` | `str` | Identification of firing rule (`SSH-001`). |
| `rule_name` | `str` | Human-readable alert title. |
| `severity` | `Severity` | Enum: `info`, `low`, `medium`, `high`, `critical`. |
| `score` | `int` | Calculated risk score ($0$ to $100$). |
| `first_seen` | `datetime` | UTC timestamp of earliest contributing event. |
| `last_seen` | `datetime` | UTC timestamp of latest contributing event. |
| `count` | `int` | Number of events triggering this alert. |
| `entities` | `Dict[str, List[str]]` | Extracted IPs, users, and hosts involved. |
| `evidence` | `List[Event]` | Sample events demonstrating malicious activity. |
| `mitre` | `Dict[str, str]` | Tactic and Technique IDs. |
| `explanation` | `str` | Plain English rationale for the alert. |
| `recommended_action`| `str` | Playbook recommendations for SOC analyst. |
| `status` | `AlertStatus` | Enum: `new`, `triaged`, `false_positive`, `resolved`. |
