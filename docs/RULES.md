# Rule Authoring & Tuning Guide

SentinelLog uses human-readable, declarative YAML detection rules.

## Rule Structure Overview
Every rule contains:
- `id`: Unique identifier (e.g., `SSH-001`, `WEB-004`, `WIN-010`).
- `name`: Short, descriptive alert title.
- `description`: Explains what activity was observed.
- `severity`: One of `info`, `low`, `medium`, `high`, `critical`.
- `mitre`: Tactic and technique mapping according to the MITRE ATT&CK framework.
- `log_source`: Telemetry type (`ssh_auth`, `web_access`, `windows_security`, `syslog`).
- `type`: Detection strategy (`match`, `threshold`, `sequence`, `anomaly`, `intel`).
- `detection`: Specific match criteria or threshold parameters.
- `response`: Recommended actions for the SOC analyst.
- `tests`: Fixture logs demonstrating when the rule should and should not fire.

## Rule Tuning & False Positive Suppression
Security rules often alert on authorized administrative activity. SentinelLog provides:
1. `exceptions` blocks inside rules to ignore specific subnets or service accounts.
2. Global suppression via `config/allowlist.yaml`.
