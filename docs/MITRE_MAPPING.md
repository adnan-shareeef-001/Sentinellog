# MITRE ATT&CK® Mapping Matrix

This table maps SentinelLog's detection capabilities to the industry-standard MITRE ATT&CK matrix.

| Rule ID | Rule Name | Log Source | MITRE Tactic | MITRE Technique ID | Technique Name |
|---|---|---|---|---|---|
| `SSH-001` | SSH Brute Force from Single Source | `ssh_auth` | Credential Access | `T1110.001` | Password Guessing |
| `SSH-002` | SSH Password Spraying | `ssh_auth` | Credential Access | `T1110.003` | Password Spraying |
| `SSH-003` | SSH Successful Login After Failures | `ssh_auth` | Initial Access | `T1078` | Valid Accounts |
| `SSH-004` | Direct SSH Root Login Attempt | `ssh_auth` | Privilege Escalation | `T1078.003` | Local Accounts |
| `WEB-001` | SQL Injection Pattern in Query | `web_access` | Initial Access | `T1190` | Exploit Public-Facing Application |
| `WEB-002` | Directory / Path Traversal Attempt | `web_access` | Initial Access | `T1190` | Exploit Public-Facing Application |
| `WEB-003` | Automated Vulnerability Scanner Detected | `web_access` | Reconnaissance | `T1595.002` | Vulnerability Scanning |
| `WEB-004` | HTTP 404 Burst (Directory Enumeration) | `web_access` | Reconnaissance | `T1595` | Active Scanning |
| `WIN-001` | Windows Failed Logon Burst (4625) | `windows_security` | Credential Access | `T1110.001` | Password Guessing |
| `WIN-002` | Windows Security Audit Log Cleared (1102) | `windows_security` | Defense Evasion | `T1070.001` | Clear Windows Event Logs |
| `WIN-003` | Local User Account Created (4720) | `windows_security` | Persistence | `T1136.001` | Local Account |
| `WIN-004` | User Added to Local Administrators (4732) | `windows_security` | Privilege Escalation | `T1098` | Account Manipulation |
| `WIN-005` | Suspicious Process Spawned (4688) | `windows_security` | Execution | `T1059.001` | PowerShell |
