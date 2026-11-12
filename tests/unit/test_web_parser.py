"""Unit tests for the Apache/Nginx Combined web access log parser."""

from sentinellog.parsers.base import ParseContext
from sentinellog.parsers.web_access import WebAccessParser


def test_web_parser_get_success() -> None:
    """Verify parsing standard GET request with user and user agent."""
    parser = WebAccessParser()
    ctx = ParseContext()
    line = (
        '10.0.0.15 - devops [13/Oct/2026:10:14:20 +0000] "GET /index.html HTTP/1.1" '
        '200 4523 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    )
    event = parser.parse(line, "access.log", 1, ctx)

    assert event is not None
    assert event.source_type == "web_access"
    assert event.event_type == "http_request"
    assert event.src_ip == "10.0.0.15"
    assert event.user == "devops"
    assert event.http_method == "GET"
    assert event.url == "/index.html"
    assert event.status_code == 200
    assert event.bytes_out == 4523
    assert event.user_agent == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    assert ctx.parsed_events == 1
    assert ctx.bad_lines == 0


def test_web_parser_url_percent_decoding() -> None:
    """Verify URL percent-decoding handles encoded characters cleanly."""
    parser = WebAccessParser()
    ctx = ParseContext()
    line = (
        "198.51.100.50 - - [13/Oct/2026:10:15:05 +0000] "
        '"GET /search?q=%27%20OR%201%3D1-- HTTP/1.1" 500 892 "-" "sqlmap/1.7"'
    )
    event = parser.parse(line, "access.log", 2, ctx)

    assert event is not None
    assert event.url == "/search?q=' OR 1=1--"
    assert event.status_code == 500
    assert event.user is None  # "-" should be normalized to None


def test_web_parser_malformed_line() -> None:
    """Verify unparseable web log line returns None and increments bad_lines."""
    parser = WebAccessParser()
    ctx = ParseContext()
    line = "BAD WEB LOG LINE MISSING HTTP FORMAT"
    event = parser.parse(line, "access.log", 3, ctx)

    assert event is None
    assert ctx.bad_lines == 1


def test_web_parser_probe() -> None:
    """Verify probe returns True for Combined log format, False for SSH."""
    parser = WebAccessParser()
    web_line = '10.0.0.1 - - [13/Oct/2026:10:14:20 +0000] "GET / HTTP/1.1" 200 123'
    ssh_line = "Oct 13 10:14:02 srv-prod-01 sshd[28410]: Failed password for root..."
    assert parser.probe(web_line) is True
    assert parser.probe(ssh_line) is False
