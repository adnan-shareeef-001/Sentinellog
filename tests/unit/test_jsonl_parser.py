"""Unit tests for the configurable JSON Lines parser."""

import json

from sentinellog.parsers.jsonl import JSONLParser


def test_jsonl_probe() -> None:
    parser = JSONLParser()
    valid_json = json.dumps({"action": "login", "user": "alice"})
    assert parser.probe(valid_json) is True
    assert parser.probe("not json string") is False


def test_jsonl_parse_standard() -> None:
    parser = JSONLParser()
    line = json.dumps(
        {
            "timestamp": "2026-10-13T10:00:00Z",
            "event_type": "auth_failure",
            "host": "srv01",
            "user": "bob",
            "src_ip": "1.2.3.4",
        }
    )
    event = parser.parse(line, "app.jsonl", 1)
    assert event is not None
    assert event.source_type == "jsonl"
    assert event.event_type == "auth_failure"
    assert event.host == "srv01"
    assert event.user == "bob"
    assert event.src_ip == "1.2.3.4"


def test_jsonl_custom_field_map() -> None:
    parser = JSONLParser(field_map={"user": "actor_name", "src_ip": "client_ip"})
    line = json.dumps(
        {
            "actor_name": "charlie",
            "client_ip": "9.9.9.9",
        }
    )
    event = parser.parse(line, "custom.jsonl", 1)
    assert event is not None
    assert event.user == "charlie"
    assert event.src_ip == "9.9.9.9"
