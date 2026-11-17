# SentinelLog Detection Rules Catalog

SentinelLog includes 22 production-grade detection rules categorized across Linux SSH/auth, Web access, Windows Event Logs / Sysmon, and Generic Cross-Source Threat Intel.

---

## Rule Inventory Summary

| ID | Name | Severity | Source | Type | MITRE Technique |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **GEN-001** | Inbound Traffic from Threat Intel Blocklist | High | All | Match | T1071 (Application Layer Protocol) |
| **SSH-001** | SSH Brute-Force Password Guessing | High | SSH | Threshold | T1110.001 (Password Guessing) |
| **SSH-002** | Successful Login After Repeated Failures | Critical | SSH | Sequence | T1110 (Brute Force) |
| **SSH-003** | SSH Multi-Account Spray Attack | High | SSH | Threshold | T1110.003 (Password Spraying) |
| **SSH-004** | Root Login Attempt via SSH | Medium | SSH | Match | T1078 (Valid Accounts) |
| **SSH-005** | High Frequency Sudo Execution Failure | Medium | SSH | Threshold | T1078.003 (Local Accounts) |
| **SSH-006** | Anomalous Off-Hours Admin Login | Medium | SSH | Anomaly | T1078 (Valid Accounts) |
| **SSH-007** | SSH Distributed Password Guessing | High | SSH | Threshold | T1110.001 (Password Guessing) |
| **WEB-001** | SQL Injection Pattern in HTTP Request | High | Web | Match | T1190 (Exploit Public-Facing Application) |
| **WEB-002** | Cross-Site Scripting (XSS) Payload | Medium | Web | Match | T1189 (Drive-by Compromise) |
| **WEB-003** | Directory / Path Traversal Pattern | High | Web | Match | T1083 (File and Directory Discovery) |
| **WEB-004** | Web Directory Bruteforce / Discovery Scan | Medium | Web | Threshold | T1595.002 (Vulnerability Scanning) |
| **WEB-005** | Anomalous Web Request Rate Spike (Z-Score) | Medium | Web | Anomaly | T1499 (Endpoint Denial of Service) |
| **WEB-006** | Shell Injection and RCE Pattern | Critical | Web | Match | T1059 (Command and Scripting Interpreter) |
| **WEB-007** | Web Server Error Rate Spike (5xx Errors) | Low | Web | Threshold | T1499 (Endpoint DoS) |
| **WIN-001** | Windows Account Lockout Spike (Event 4740) | Medium | Windows | Threshold | T1110.001 (Password Guessing) |
| **WIN-002** | Security Audit Log Cleared (Event 1102) | Critical | Windows | Match | T1070.001 (Clear Windows Event Logs) |
| **WIN-003** | User Added to High-Privilege Domain Group | High | Windows | Match | T1098 (Account Manipulation) |
| **WIN-004** | Suspicious LSASS Process Access | Critical | Windows | Match | T1003.001 (LSASS Memory) |
| **WIN-005** | Suspicious Scheduled Task Creation | Medium | Windows | Match | T1053.005 (Scheduled Task) |
| **WIN-006** | Mimikatz / Sekurlsa Command Execution | Critical | Windows | Match | T1003.001 (LSASS Memory) |
| **WIN-007** | Base64 Encoded PowerShell Command Execution | High | Windows | Match | T1059.001 (PowerShell) |

---

## Rule Details

### Generic Threat Intel
#### `GEN-001`: Inbound Traffic from Threat Intel Blocklist
- **Severity**: High
- **Log Source**: `all`
- **Engine Type**: `match` (Threat Intel blocklist match on source IP)
- **MITRE**: T1071 (Command and Control: Application Layer Protocol)
- **Explanation**: Detects communication or login attempts originating from known malicious IP addresses present in the local threat intelligence blocklists.
- **Recommended Action**: Block the offending IP at the edge firewall/WAF. Check active sessions for signs of compromise.

---

### SSH / Linux Authentication
#### `SSH-001`: SSH Brute-Force Password Guessing
- **Severity**: High
- **Log Source**: `ssh`
- **Engine Type**: `threshold` (count >= 5 within 120s grouped by `source_ip`)
- **MITRE**: T1110.001 (Credential Access: Password Guessing)
- **Explanation**: A single IP address triggered 5 or more SSH authentication failures within 2 minutes.
- **Recommended Action**: Add IP to temporary fail2ban jail or firewall drop list; inspect affected user accounts.

#### `SSH-002`: Successful Login After Repeated Failures
- **Severity**: Critical
- **Log Source**: `ssh`
- **Engine Type**: `sequence` (repeated failed logins followed by successful login within 300s)
- **MITRE**: T1110 (Credential Access: Brute Force)
- **Explanation**: Multiple failed password attempts from an IP were immediately followed by a successful login. Strong indicator of compromised credentials.
- **Recommended Action**: Immediately terminate active user session, revoke SSH keys/passwords, and audit user activity.

#### `SSH-003`: SSH Multi-Account Spray Attack
- **Severity**: High
- **Log Source**: `ssh`
- **Engine Type**: `threshold` (count >= 4 unique target users within 180s grouped by `source_ip`)
- **MITRE**: T1110.003 (Credential Access: Password Spraying)
- **Explanation**: A single IP attempted logins across 4 or more different usernames within 3 minutes to avoid per-user lockout thresholds.
- **Recommended Action**: Enforce multi-factor authentication (MFA); block source IP at network perimeter.

#### `SSH-004`: Root Login Attempt via SSH
- **Severity**: Medium
- **Log Source**: `ssh`
- **Engine Type**: `match` (`user == "root"`)
- **MITRE**: T1078 (Defense Evasion / Initial Access: Valid Accounts)
- **Explanation**: Direct root SSH login attempt detected. Direct root login is contrary to security hardening standards.
- **Recommended Action**: Ensure `PermitRootLogin no` is configured in `/etc/ssh/sshd_config`.

#### `SSH-005`: High Frequency Sudo Execution Failure
- **Severity**: Medium
- **Log Source**: `ssh`
- **Engine Type**: `threshold` (count >= 3 within 60s grouped by `user`)
- **MITRE**: T1078.003 (Privilege Escalation: Local Accounts)
- **Explanation**: A user failed repeated sudo password verifications within 60 seconds, indicating local brute-force or unauthorized privilege escalation attempt.
- **Recommended Action**: Contact user to verify legitimacy; inspect shell history and cron jobs.

#### `SSH-006`: Anomalous Off-Hours Admin Login
- **Severity**: Medium
- **Log Source**: `ssh`
- **Engine Type**: `anomaly` (`off_hours` detection between 22:00 and 06:00 UTC)
- **MITRE**: T1078 (Valid Accounts)
- **Explanation**: Privileged or administrative account successfully authenticated during abnormal off-hours window.
- **Recommended Action**: Confirm with account owner whether out-of-hours maintenance was pre-authorized.

#### `SSH-007`: SSH Distributed Password Guessing
- **Severity**: High
- **Log Source**: `ssh`
- **Engine Type**: `threshold` (count >= 8 failures across distinct IPs within 300s grouped by target `user`)
- **MITRE**: T1110.001 (Password Guessing)
- **Explanation**: A single account was targeted by failed logins from multiple distinct IP addresses simultaneously (distributed botnet attack).
- **Recommended Action**: Temporarily lock target account and reset credentials; enforce IP allowlists or client certificates.

---

### Web Application Access
#### `WEB-001`: SQL Injection Pattern in HTTP Request
- **Severity**: High
- **Log Source**: `web`
- **Engine Type**: `match` (regex matching SQL syntax: `union\s+select`, `information_schema`, `--`, `' OR '1'='1`)
- **MITRE**: T1190 (Initial Access: Exploit Public-Facing Application)
- **Explanation**: Inbound HTTP request contains SQL keywords and syntax typical of SQL injection exploitation.
- **Recommended Action**: Verify backend database parameterization; inspect response status code and length.

#### `WEB-002`: Cross-Site Scripting (XSS) Payload
- **Severity**: Medium
- **Log Source**: `web`
- **Engine Type**: `match` (regex matching `<script>`, `javascript:`, `onerror=`, `onload=`)
- **MITRE**: T1189 (Drive-by Compromise)
- **Explanation**: Inbound request URL or query contains client-side script tags or JavaScript execution handlers.
- **Recommended Action**: Ensure HTML entity encoding and Content Security Policy (CSP) headers are enforced.

#### `WEB-003`: Directory / Path Traversal Pattern
- **Severity**: High
- **Log Source**: `web`
- **Engine Type**: `match` (regex matching `../`, `..%2f`, `/etc/passwd`, `/windows/win.ini`)
- **MITRE**: T1083 (Discovery: File and Directory Discovery)
- **Explanation**: Request URI attempts to escape web root directories using path traversal encodings.
- **Recommended Action**: Inspect server file permissions and web server path normalization settings.

#### `WEB-004`: Web Directory Bruteforce / Discovery Scan
- **Severity**: Medium
- **Log Source**: `web`
- **Engine Type**: `threshold` (count >= 15 HTTP 404/403 responses within 60s grouped by `source_ip`)
- **MITRE**: T1595.002 (Reconnaissance: Vulnerability Scanning)
- **Explanation**: Rapid succession of non-existent resource requests indicative of automated scanners (Gobuster, Dirbuster).
- **Recommended Action**: Rate-limit or block scanner IP at reverse proxy/WAF.

#### `WEB-005`: Anomalous Web Request Rate Spike (Z-Score)
- **Severity**: Medium
- **Log Source**: `web`
- **Engine Type**: `anomaly` (Z-score rate spike > 3.0 standard deviations from baseline)
- **MITRE**: T1499 (Impact: Endpoint Denial of Service)
- **Explanation**: Unusually high volume of web requests from an IP compared to dynamic sliding baseline.
- **Recommended Action**: Investigate potential Layer 7 DDoS, automated scraping, or data exfiltration.

#### `WEB-006`: Shell Injection and Remote Code Execution Pattern
- **Severity**: Critical
- **Log Source**: `web`
- **Engine Type**: `match` (regex matching `/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell`, `wget`, `curl\s+http`)
- **MITRE**: T1059 (Execution: Command and Scripting Interpreter)
- **Explanation**: Web request includes commands attempting remote command execution on the host operating system.
- **Recommended Action**: Isolate web application instance, audit host processes, check for web shell persistence.

#### `WEB-007`: Web Server Error Rate Spike (5xx Errors)
- **Severity**: Low
- **Log Source**: `web`
- **Engine Type**: `threshold` (count >= 20 HTTP 5xx responses within 120s)
- **MITRE**: T1499 (Impact: Endpoint Denial of Service)
- **Explanation**: Sudden surge in server-side application errors indicative of application crashes or active fuzzing.
- **Recommended Action**: Review application exception logs and database connectivity.

---

### Windows Event Logs & Sysmon
#### `WIN-001`: Windows Account Lockout Spike (Event 4740)
- **Severity**: Medium
- **Log Source**: `windows`
- **Engine Type**: `threshold` (count >= 3 lockout events within 180s)
- **MITRE**: T1110.001 (Credential Access: Password Guessing)
- **Explanation**: Multiple accounts locked out in quick succession due to repeated incorrect password entries.
- **Recommended Action**: Inspect domain controller logs to locate source workstation/IP initiating lockouts.

#### `WIN-002`: Security Audit Log Cleared (Event 1102)
- **Severity**: Critical
- **Log Source**: `windows`
- **Engine Type**: `match` (Event ID 1102 / 104)
- **MITRE**: T1070.001 (Defense Evasion: Clear Windows Event Logs)
- **Explanation**: Security log was deliberately cleared, strongly suggesting anti-forensic action by an adversary.
- **Recommended Action**: Immediately isolate affected endpoint and trigger incident response triage.

#### `WIN-003`: User Added to High-Privilege Domain Group
- **Severity**: High
- **Log Source**: `windows`
- **Engine Type**: `match` (Event ID 4728: Member added to Domain Admins, Enterprise Admins, or Schema Admins)
- **MITRE**: T1098 (Persistence / Privilege Escalation: Account Manipulation)
- **Explanation**: A user was added to a privileged security group.
- **Recommended Action**: Verify change management approval; revoke membership if unauthorized.

#### `WIN-004`: Suspicious LSASS Process Access
- **Severity**: Critical
- **Log Source**: `windows`
- **Engine Type**: `match` (Event ID 4656 / 4663 / Sysmon 10 targeting `lsass.exe`)
- **MITRE**: T1003.001 (Credential Access: LSASS Memory)
- **Explanation**: An unauthorized non-system process requested access to LSASS process memory.
- **Recommended Action**: Memory dump analysis, terminate originating process, reset compromised domain credentials.

#### `WIN-005`: Suspicious Scheduled Task Creation
- **Severity**: Medium
- **Log Source**: `windows`
- **Engine Type**: `match` (Event ID 4698 creating task with script interpreter or hidden execution)
- **MITRE**: T1053.005 (Persistence: Scheduled Task)
- **Explanation**: A new scheduled task was registered executing scripts or binary payloads outside standard system directories.
- **Recommended Action**: Review task command line, user author, and scheduled trigger times.

#### `WIN-006`: Mimikatz / Sekurlsa Command Execution
- **Severity**: Critical
- **Log Source**: `windows`
- **Engine Type**: `match` (Sysmon 1 / Event 4688 matching `sekurlsa`, `lsadump`, `privilege::debug`, `kerberos::golden`)
- **MITRE**: T1003.001 (Credential Access: LSASS Memory)
- **Explanation**: Command line parameters match known Mimikatz credential theft commands.
- **Recommended Action**: Disconnect machine from network, rotate administrative credentials across domain.

#### `WIN-007`: Base64 Encoded PowerShell Command Execution
- **Severity**: High
- **Log Source**: `windows`
- **Engine Type**: `match` (Sysmon 1 matching `powershell` with `-enc`, `-encodedcommand`, or `-e`)
- **MITRE**: T1059.001 (Execution: PowerShell)
- **Explanation**: PowerShell executed with base64 encoded arguments commonly used to obfuscate malicious payloads.
- **Recommended Action**: Decode base64 string, analyze invoked cmdlets/URLs, and check child process activity.
