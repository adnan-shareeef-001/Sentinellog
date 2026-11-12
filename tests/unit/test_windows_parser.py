"""Unit tests for the Windows Security Event Log parser."""

import json

from sentinellog.parsers.windows import WindowsParser


def test_windows_probe_json() -> None:
    parser = WindowsParser()
    valid_json = json.dumps({"EventID": 4624, "Computer": "DC01"})
    assert parser.probe(valid_json) is True
    assert parser.probe("Feb 10 10:00:00 host sshd: msg") is False


def test_windows_probe_csv() -> None:
    parser = WindowsParser()
    csv_line = "2026-10-13 10:00:00,4625,DC01,administrator,192.168.1.100,3"
    assert parser.probe(csv_line) is True


def test_windows_parse_json_logon_failure() -> None:
    parser = WindowsParser()
    raw = json.dumps(
        {
            "TimeCreated": "2026-10-13T10:00:00Z",
            "EventID": 4625,
            "Computer": "DC01",
            "TargetUserName": "admin",
            "IpAddress": "198.51.100.4",
            "LogonType": 3,
        }
    )
    event = parser.parse(raw, "security.jsonl", 1)
    assert event is not None
    assert event.event_type == "auth_failure"
    assert event.event_id == 4625
    assert event.user == "admin"
    assert event.src_ip == "198.51.100.4"
    assert event.logon_type == 3
    assert event.host == "DC01"


def test_windows_parse_nested_event() -> None:
    parser = WindowsParser()
    raw = json.dumps(
        {
            "Event": {
                "System": {
                    "EventID": {"#text": 1102},
                    "TimeCreated": {"SystemTime": "2026-10-13T10:15:00Z"},
                    "Computer": "DC01",
                },
                "EventData": {
                    "SubjectUserName": "backdoor_admin",
                },
            }
        }
    )
    event = parser.parse(raw, "security.jsonl", 2)
    assert event is not None
    assert event.event_type == "log_cleared"
    assert event.event_id == 1102
    assert event.user == "backdoor_admin"


def test_windows_parse_csv() -> None:
    parser = WindowsParser()
    csv_line = (
        '2026-10-13 10:00:00,4688,DC01,admin,10.0.0.1,2,powershell.exe,"powershell.exe -enc test"'
    )
    event = parser.parse(csv_line, "security.csv", 3)
    assert event is not None
    assert event.event_type == "process_created"
    assert event.event_id == 4688
    assert event.process == "powershell.exe"
    assert event.command_line == "powershell.exe -enc test"


def test_windows_clean_ip_normalization() -> None:
    parser = WindowsParser()
    raw = json.dumps(
        {
            "TimeCreated": "2026-10-13T10:00:00Z",
            "EventID": 4624,
            "Computer": "DC01",
            "IpAddress": "-",
        }
    )
    event = parser.parse(raw, "security.jsonl", 4)
    assert event is not None
    assert event.src_ip is None
