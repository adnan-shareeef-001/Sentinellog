# Changelog

All notable changes to **SentinelLog** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-17

### Added
- **Interactive SOC Dashboard (`sentinellog dashboard`)**:
  - Streamlit-based web console with 4 dedicated analyst workflows: Incident Triage, Threat Hunting workbench, MITRE ATT&CK Matrix coverage, and an interactive Rule Catalog.
  - Multi-status incident workflow management (`open`, `investigating`, `resolved`, `false_positive`).
- **High-Throughput Optimization & Stress Benchmarks**:
  - Achieved **20,842 - 33,660 events/second** throughput on 100,000 log lines.
  - Sub-microsecond syslog timestamp parsing and rule log-source indexing in `DetectionEngine`.
- **Statistical Anomaly Detection Engine**:
  - Sliding-window Z-Score rate spike detector (`WEB-005`).
  - Off-hours administrative login evaluation (`SSH-006`).
- **Air-Gapped Executive HTML Report (`sentinellog report`)**:
  - Self-contained, responsive executive HTML report built with embedded pure CSS without any external CDN, font, or script calls.
- **Real-Time Log Ingestion (`sentinellog tail`)**:
  - Non-blocking log follower with automatic file rotation and truncation detection.
- **Context & Threat Intelligence Enrichment**:
  - Local threat intelligence blocklists (`intel.py`) with matching rule `GEN-001`.
  - Internal asset inventory (`assets.py`) mapping IPs/hosts to criticality tiers and owner departments.
  - Air-gapped GeoIP subnet fallback resolver (`geoip.py`).
- **Incident Correlation & SQLite Storage**:
  - Multi-factor composite risk scoring formula (0–100 scale).
  - 10-minute sliding deduplication engine.
  - Incident correlation grouping related alerts by primary entities.
  - Persistent SQLite forensic alert and incident store (`store.py`).
- **Extended Parser Suite & Multi-Stage State Machine**:
  - Windows Event Log (EVTX/JSON) and Sysmon parser (`windows.py`).
  - RFC 3164 / 5424 Syslog parser (`syslog.py`).
  - Multi-stage sequence state machine (`sequence.py`) for multi-step attack detection (e.g. `SSH-002`).
- **Detection Rules Expansion**:
  - Total 22 production-grade rules covering Linux, Web, Windows/Sysmon, and Threat Intel.
- **Synthetic Attack Simulator & Metrics Evaluation**:
  - `sentinellog simulate` generating realistic normal and adversary scenarios with ground-truth `labels.json`.
  - `sentinellog evaluate` computing true/false positives, precision, recall, and F1-score.
- **Production CI Matrix**:
  - GitHub Actions matrix workflow testing on Ubuntu and Windows across Python 3.11, 3.12, and 3.13.

---

## [0.1.0] - 2026-10-13

### Added
- Project foundation, structure, and operational standards (`AGENTS.md`).
- Multi-OS GitHub Actions CI workflow (Windows and Ubuntu on Python 3.11 & 3.12).
- Toolchain configuration for `ruff`, `mypy`, `pytest`, and `pre-commit`.
- Base CLI structure with `typer` and `rich` including `doctor` diagnostic command.
- Foundational documentation and glossary.
