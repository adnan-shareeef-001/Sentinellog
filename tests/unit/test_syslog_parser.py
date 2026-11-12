"""Unit tests for the generic Syslog parser (RFC3164 and RFC5424)."""

from sentinellog.parsers.syslog import SyslogParser


def test_syslog_probe_rfc3164() -> None:
    parser = SyslogParser()
    line = "Oct 13 10:14:00 myhost systemd[1]: Started Service."
    assert parser.probe(line) is True
    assert parser.probe("127.0.0.1 - - [13/Oct/2026] GET / HTTP/1.1") is False


def test_syslog_probe_rfc5424() -> None:
    parser = SyslogParser()
    line = "<34>1 2026-10-13T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed"
    assert parser.probe(line) is True


def test_syslog_parse_rfc3164() -> None:
    parser = SyslogParser()
    line = "Oct 13 10:14:00 myhost cron[1234]: (root) CMD (/usr/local/bin/backup)"
    event = parser.parse(line, "syslog.log", 1)
    assert event is not None
    assert event.source_type == "syslog"
    assert event.host == "myhost"
    assert event.process == "cron"


def test_syslog_parse_rfc5424() -> None:
    parser = SyslogParser()
    line = "<165>1 2026-10-13T22:14:15.003Z myhost myapp 1234 ID47 [exampleSDID@32473 iut='3'] msg"
    event = parser.parse(line, "syslog.log", 2)
    assert event is not None
    assert event.source_type == "syslog"
    assert event.host == "myhost"
    assert event.process == "myapp"
