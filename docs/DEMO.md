# SentinelLog: 5-Minute Demonstration Walkthrough

This guide provides a rapid demonstration script showcasing SentinelLog's detection capabilities, streaming ingestion, accuracy benchmarking, and defense-in-depth features.

---

## 1. System Health & Environment Check (30 seconds)

Verify that all dependencies, configurations, threat intelligence blocklists, and detection rules are healthy:
```powershell
sentinellog doctor
```
*Expected Result*: Diagnostic table passes Python version check ($\ge$ 3.11), confirms presence of `config/sentinellog.yaml`, `config/allowlist.yaml`, `config/assets.yaml`, rule directories, and synthetic threat feeds.

---

## 2. Rule Validation & Regression Testing (45 seconds)

Validate that all YAML detection rules adhere to the Pydantic schema and satisfy their positive (`should_fire`) and negative (`should_not_fire`) log fixtures:
```powershell
# Validate YAML schema and regex ReDoS safety
sentinellog rules validate

# Execute positive and negative test fixture assertions
sentinellog rules test
```
*Expected Result*: All 11 rules pass schema verification and fixture testing with zero false positives.

---

## 3. Synthetic Traffic & Attack Simulation (45 seconds)

Generate a realistic multi-source dataset containing 95% benign background traffic intermixed with distinct attack scenarios (`brute_force`, `spraying`, `web_attack`):
```powershell
sentinellog simulate --scenario mixed --out data/generated --seed 42
```
*Expected Result*: Generates `data/generated/auth.log`, `access.log`, and ground-truth `labels.json` detailing malicious line numbers and expected rule IDs.

---

## 4. Threat Detection Scan & Triage Output (60 seconds)

Run the detection engine against the simulated logs, streaming events through the reorder buffer and outputting Rich alerts and machine-readable JSON:
```powershell
sentinellog scan data/generated --rules rules/ --out data/generated/report.json
```
*Expected Result*:
- Real-time Rich alert table categorized by severity.
- Deep detail panels showing MITRE ATT&CK techniques, analyst action steps, and exact raw log evidence references.
- Execution summary highlighting throughput ($> 7,000$ events/second).

---

## 5. Ground-Truth Accuracy & Statistical Audit (60 seconds)

Audit the engine's precision and recall against ground truth:
```powershell
sentinellog stats data/generated
```
*Expected Result*:
- Breakdown of parsed events and bad lines.
- Benchmark Accuracy Table showing **100% Scenario Recall** and **100% Alert Precision**.
