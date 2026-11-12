# SentinelLog Learning Log

This file tracks key architectural lessons, security takeaways, and engineering insights gained during each phase of development.

---

## 📌 Phase 0: Foundations & The SOC Workflow

### What I Learned About the SOC Workflow
1. **The Telemetry Funnel:** Real enterprise systems generate gigabytes of logs per minute. A SOC cannot review every raw log line manually. Instead, telemetry passes through a funnel:
   $$\text{Raw Logs} \longrightarrow \text{Normalized Events} \longrightarrow \text{Alerts} \longrightarrow \text{Incidents}$$
2. **Defensive Posture & Input Hygiene:** Security software is an attractive target for adversaries. If a security parser crashes when given unexpected input (or freezes due to ReDoS), the attacker has successfully blinded the SOC. Defensive tools must be resilient, cap line sizes, escape output, and handle errors without terminating.
3. **Evidence Provenance:** An alert is useless unless an analyst can verify it. Capturing the source filename, line number, and raw snippet is vital for investigation and legal forensics.
4. **Cross-Platform Engineering:** In enterprise environments, analysts work on Windows and Linux workstations while servers run across diverse cloud operating systems. Using `pathlib.Path` and automated multi-OS CI ensures our tool works everywhere without hardcoded path bugs.
