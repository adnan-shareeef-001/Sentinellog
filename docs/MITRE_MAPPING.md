# MITRE ATT&CK® Mapping Matrix

This table maps SentinelLog's detection rules to the industry-standard MITRE ATT&CK matrix.

| Rule ID | Rule Name | Severity | Type | Log Source | MITRE Tactic | MITRE Technique ID | Technique Name |
|---|---|---|---|---|---|---|---|
| `GEN-001` | Known threat intelligence blocklisted IP communication | High | Match | `any` | Command and Control | `T1071` | Application Layer Protocol |
| `SSH-001` | SSH brute force from a single source | High | Threshold | `ssh_auth` | Credential Access | `T1110.001` | Password Guessing |
| `SSH-002` | SSH password spraying across distinct accounts | High | Threshold | `ssh_auth` | Credential Access | `T1110.003` | Password Spraying |
| `SSH-003` | SSH brute force followed by successful authentication | Critical | Sequence | `ssh_auth` | Initial Access | `T1078` | Valid Accounts |
| `SSH-004` | Direct root SSH login attempt | High | Match | `ssh_auth` | Privilege Escalation | `T1078.003` | Local Accounts |
| `SSH-005` | Enumeration of invalid SSH usernames | Medium | Threshold | `ssh_auth` | Reconnaissance | `T1087.001` | Local Account Discovery |
| `SSH-006` | Successful SSH login outside business hours | Medium | Anomaly | `ssh_auth` | Initial Access | `T1078` | Valid Accounts |
| `SSH-007` | Sudo execution of interactive shell or privilege editor | Critical | Match | `ssh_auth` | Privilege Escalation | `T1548.003` | Sudo and Sudo Caching |
| `WEB-001` | SQL injection attempt in URL parameter | High | Match | `web_access` | Initial Access | `T1190` | Exploit Public-Facing Application |
| `WEB-002` | Path traversal directory climbing in URL | High | Match | `web_access` | Initial Access | `T1190` | Exploit Public-Facing Application |
| `WEB-003` | Automated vulnerability scanner user agent | Medium | Match | `web_access` | Reconnaissance | `T1595.002` | Vulnerability Scanning |
| `WEB-004` | High rate of HTTP 404 Not Found responses | Medium | Threshold | `web_access` | Reconnaissance | `T1595` | Active Scanning |
| `WEB-005` | Abnormal spike in HTTP 5xx server error responses | High | Anomaly | `web_access` | Impact | `T1499` | Endpoint Denial of Service |
| `WEB-006` | Probing for sensitive configuration files or administrative panels | High | Match | `web_access` | Initial Access | `T1190` | Exploit Public-Facing Application |
| `WEB-007` | Remote command execution probe in URL parameter | Critical | Match | `web_access` | Initial Access | `T1190` | Exploit Public-Facing Application |
| `WIN-001` | Windows multiple logon failures from a single source | High | Threshold | `windows` | Credential Access | `T1110.001` | Password Guessing |
| `WIN-002` | Successful external Remote Desktop logon | High | Match | `windows` | Initial Access | `T1078.002` | Domain Accounts |
| `WIN-003` | Local or domain user account created | Medium | Match | `windows` | Persistence | `T1136.001` | Local Account |
| `WIN-004` | User added to local security group | High | Match | `windows` | Privilege Escalation | `T1098` | Account Manipulation |
| `WIN-005` | Windows audit log cleared | Critical | Match | `windows` | Defense Evasion | `T1070.001` | Clear Windows Event Logs |
| `WIN-006` | Suspicious encoded PowerShell or LOLBAS execution | High | Match | `windows` | Execution | `T1059.001` | PowerShell |
| `WIN-007` | Windows brute force followed by successful logon | Critical | Sequence | `windows` | Initial Access | `T1078` | Valid Accounts |

## Coverage by Tactic Summary
- **Initial Access**: `SSH-003`, `SSH-006`, `WEB-001`, `WEB-002`, `WEB-006`, `WEB-007`, `WIN-002`, `WIN-007`
- **Execution**: `WIN-006`
- **Persistence**: `WIN-003`
- **Privilege Escalation**: `SSH-004`, `SSH-007`, `WIN-004`
- **Defense Evasion**: `WIN-005`
- **Credential Access**: `SSH-001`, `SSH-002`, `WIN-001`
- **Reconnaissance**: `SSH-005`, `WEB-003`, `WEB-004`
- **Command and Control**: `GEN-001`
- **Impact**: `WEB-005`
