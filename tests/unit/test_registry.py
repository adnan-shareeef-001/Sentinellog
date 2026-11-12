"""Unit tests for the parser registry and auto-detection heuristics."""

import pytest

from sentinellog.parsers.registry import detect_format, get_parser


def test_get_parser() -> None:
    """Verify retrieving parsers by canonical name and aliases."""
    ssh = get_parser("ssh_auth")
    assert ssh.name == "ssh_auth"

    ssh_alias = get_parser("ssh")
    assert ssh_alias.name == "ssh_auth"

    web = get_parser("web_access")
    assert web.name == "web_access"

    web_alias = get_parser("web")
    assert web_alias.name == "web_access"

    with pytest.raises(KeyError, match="Unknown parser format"):
        get_parser("unknown_xyz")


def test_detect_format_ssh() -> None:
    """Verify auto-detection identifies SSH logs with >= 60% match rate."""
    ssh_lines = [
        "Oct 13 10:14:02 srv sshd[28410]: Failed password for root from 198.51.100.4 port 41234",
        "Oct 13 10:14:05 srv sshd[28411]: Failed password for admin from 198.51.100.4 port 41235",
        "Oct 13 10:14:09 srv sshd[28412]: Invalid user test from 198.51.100.4 port 41240",
    ]
    detected = detect_format(ssh_lines)
    assert detected == "ssh_auth"


def test_detect_format_web() -> None:
    """Verify auto-detection identifies web logs with >= 60% match rate."""
    web_lines = [
        '10.0.0.1 - - [13/Oct/2026:10:14:20 +0000] "GET / HTTP/1.1" 200 4523 "-" "Mozilla/5.0"',
        '10.0.0.2 - - [13/Oct/2026:10:14:21 +0000] "GET /login HTTP/1.1" 200 1820 "-" "curl/7.88"',
    ]
    detected = detect_format(web_lines)
    assert detected == "web_access"


def test_detect_format_fallback() -> None:
    """Verify fallback to syslog when lines do not meet 60% threshold."""
    random_lines = [
        "some random unformatted log line 1",
        "another ambiguous log statement 2",
    ]
    detected = detect_format(random_lines)
    assert detected == "syslog"
