# SentinelLog: 5-Minute Portfolio Demonstration Script

This script provides a concise walkthrough demonstrating SentinelLog's core features to technical interviewers or team members.

---

## ⏱️ Step-by-Step Walkthrough

### Step 1: Health & Environment Verification (30 Seconds)
```bash
sentinellog doctor
```
* **What to explain:** Show how the tool validates its environment, verifies parser readiness, and ensures all detection rules are syntactically valid before operation.

### Step 2: Ingest & Telemetry Statistics (1 Minute)
```bash
sentinellog stats data/samples/sample_auth.log
```
* **What to explain:** Explain the streaming ingestion engine, showing total lines processed, parsing success rate, and breakdown of normalized events.

### Step 3: Threat Detection Scan (1.5 Minutes)
```bash
sentinellog scan data/samples/sample_auth.log
```
* **What to explain:** Point to the color-coded severity table, MITRE technique tagging, deduplicated event counts, and exact forensic evidence (file + line number).

### Step 4: Synthetic Attack Simulation & Metrics (1 Minute)
```bash
sentinellog simulate --scenario brute_force --out data/generated/
sentinellog scan data/generated/simulated.log --ground-truth data/generated/labels.json
```
* **What to explain:** Demonstrate the attack simulation framework and show automated calculation of **Precision**, **Recall**, and **F1-Score**.

### Step 5: Incident Report Generation (1 Minute)
```bash
sentinellog scan data/generated/simulated.log --out report.html
```
* **What to explain:** Open `report.html` in a web browser to showcase the executive summary, MITRE tactic heatmap, and incident timelines.
