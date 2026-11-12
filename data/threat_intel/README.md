# Threat Intelligence Blocklists

This directory stores plain-text Indicator of Compromise (IoC) lists used by SentinelLog's enrichment engine for high-speed offline matching.

## Format
* One IP indicator per line.
* Comments begin with `#`.
* Blank lines are ignored.

```
# Source: Internal Incident 2026-09-01
198.51.100.24
203.0.113.88
```

## Free & Public Threat Intelligence Feeds You Can Download
SentinelLog is offline-first. You can download and place free public blocklists here manually:
1. **Emerging Threats Compromised IPs:**
   - URL: `https://rules.emergingthreats.net/blockrules/compromised-ips.txt`
   - Description: Top malicious IP addresses observed engaging in malware command-and-control (C2).
2. **abuse.ch Feodo Tracker (Botnet C2 IP Blocklist):**
   - URL: `https://feodotracker.abuse.ch/downloads/ipblocklist.txt`
   - Description: Active botnet controller IP addresses (Dridex, Emotet, QakBot).
3. **URLhaus Database:**
   - URL: `https://urlhaus.abuse.ch/downloads/csv/`
   - Description: Sites actively distributing malware.
