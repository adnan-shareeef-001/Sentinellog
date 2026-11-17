"""Unit tests for the HTML report generator."""

from pathlib import Path

from sentinellog.output.html_report import generate_html_report


def test_generate_html_report(tmp_path: Path) -> None:
    report_file = tmp_path / "out_report.html"

    sample_alerts = [
        {
            "id": "ALT-001",
            "rule_id": "SSH-001",
            "rule_name": "SSH Brute Force",
            "severity": "high",
            "score": 85,
            "first_seen": "2026-10-13T10:00:00Z",
            "entities": {"src_ip": ["198.51.100.4"], "user": ["admin"]},
            "mitre": {"tactic": "Credential Access", "technique": "T1110.001"},
            "recommended_action": "Block source IP",
        }
    ]

    sample_incidents = [
        {
            "id": "INC-001",
            "title": "Brute Force Attack on DC01",
            "severity": "high",
            "score": 85,
            "status": "open",
            "alert_count": 1,
            "primary_entity": "host:DC01",
            "first_seen": "2026-10-13T10:00:00Z",
        }
    ]

    out = generate_html_report(
        alerts=sample_alerts,
        incidents=sample_incidents,
        output_path=report_file,
        company_name="Test SOC",
    )

    assert out.is_file()
    content = out.read_text(encoding="utf-8")
    assert "Test SOC" in content
    assert "SSH-001" in content
    assert "INC-001" in content
    assert "198.51.100.4" in content
