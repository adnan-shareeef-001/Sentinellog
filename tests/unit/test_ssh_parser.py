"""Unit tests for the SSH authentication parser."""

from sentinellog.parsers.base import ParseContext
from sentinellog.parsers.ssh_auth import SSHAuthParser


def test_ssh_parser_failed_password_classic() -> None:
    """Verify parsing classic syslog format failed password for invalid user."""
    parser = SSHAuthParser()
    ctx = ParseContext()
    line = (
        "Oct 13 10:14:02 srv-prod-01 sshd[28410]: "
        "Failed password for invalid user admin from 198.51.100.4 port 41234 ssh2"
    )
    event = parser.parse(line, "auth.log", 1, ctx)

    assert event is not None
    assert event.source_type == "ssh_auth"
    assert event.event_type == "auth_failure"
    assert event.user == "admin"
    assert event.src_ip == "198.51.100.4"
    assert event.src_port == 41234
    assert event.host == "srv-prod-01"
    assert ctx.parsed_events == 1
    assert ctx.bad_lines == 0


def test_ssh_parser_accepted_password_iso() -> None:
    """Verify parsing ISO-8601 timestamp format accepted password."""
    parser = SSHAuthParser()
    ctx = ParseContext()
    line = (
        "2026-10-13T10:17:30.123456+00:00 srv-prod-01 sshd[28430]: "
        "Accepted password for sysadmin from 10.0.0.22 port 54112 ssh2"
    )
    event = parser.parse(line, "auth.log", 2, ctx)

    assert event is not None
    assert event.event_type == "auth_success"
    assert event.user == "sysadmin"
    assert event.src_ip == "10.0.0.22"
    assert event.src_port == 54112


def test_ssh_parser_invalid_user() -> None:
    """Verify parsing invalid user event."""
    parser = SSHAuthParser()
    ctx = ParseContext()
    line = "Oct 13 10:14:09 srv-prod-01 sshd[28412]: Invalid user test from 198.51.100.4 port 41240"
    event = parser.parse(line, "auth.log", 3, ctx)

    assert event is not None
    assert event.event_type == "invalid_user"
    assert event.user == "test"
    assert event.src_ip == "198.51.100.4"


def test_ssh_parser_sudo_command() -> None:
    """Verify parsing sudo execution log."""
    parser = SSHAuthParser()
    ctx = ParseContext()
    line = (
        "Oct 13 10:16:01 srv-prod-01 sudo:   devops : "
        "TTY=pts/0 ; PWD=/home/devops ; USER=root ; COMMAND=/bin/bash"
    )
    event = parser.parse(line, "auth.log", 4, ctx)

    assert event is not None
    assert event.event_type == "sudo_command"
    assert event.user == "devops"
    assert event.command_line == "/bin/bash"


def test_ssh_parser_malformed_line() -> None:
    """Verify unparseable line returns None and increments bad_lines."""
    parser = SSHAuthParser()
    ctx = ParseContext()
    line = "TOTAL GARBAGE LINE NOT MATCHING SSH STRUCTURE"
    event = parser.parse(line, "auth.log", 5, ctx)

    assert event is None
    assert ctx.bad_lines == 1
    assert ctx.parsed_events == 0


def test_ssh_parser_probe() -> None:
    """Verify probe returns True for SSH and sudo lines, False otherwise."""
    parser = SSHAuthParser()
    assert parser.probe("Oct 13 10:14:02 srv-prod-01 sshd[28410]: Failed password...") is True
    assert parser.probe("Oct 13 10:16:01 srv-prod-01 sudo: devops : COMMAND=/bin/ls") is True
    assert parser.probe('10.0.0.1 - - [13/Oct/2026:10:14:20 +0000] "GET /" 200 123') is False
