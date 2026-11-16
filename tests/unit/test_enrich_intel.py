"""Unit tests for the threat intelligence indicator engine."""

from pathlib import Path

from sentinellog.enrich.intel import ThreatIntelFeed


def test_intel_feed_exact_and_cidr(tmp_path: Path) -> None:
    feed_file = tmp_path / "blocklist.txt"
    feed_file.write_text(
        "# Comment line\n198.51.100.4\n203.0.113.0/24\ninvalid_entry\n",
        encoding="utf-8",
    )

    feed = ThreatIntelFeed()
    count = feed.load_file(feed_file)
    assert count == 2

    # Exact match
    assert feed.is_blocked("198.51.100.4") is True
    # Subnet match
    assert feed.is_blocked("203.0.113.55") is True
    # Non-match
    assert feed.is_blocked("10.0.0.1") is False
    assert feed.is_blocked("") is False
    assert feed.is_blocked(None) is False


def test_intel_feed_lookup_metadata(tmp_path: Path) -> None:
    feed_file = tmp_path / "feed.txt"
    feed_file.write_text("192.0.2.10\n", encoding="utf-8")

    feed = ThreatIntelFeed()
    feed.load_file(feed_file)

    meta = feed.lookup("192.0.2.10")
    assert meta is not None
    assert meta["category"] == "malicious_ip"
    assert meta["matched_by"] == "exact_ip"

    assert feed.lookup("8.8.8.8") is None
