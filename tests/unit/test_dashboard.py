"""Unit tests for the dashboard utility functions."""

from sentinellog.dashboard.app import load_data


def test_dashboard_load_data_missing_db() -> None:
    alerts, incidents = load_data("non_existent.db")
    assert alerts == []
    assert incidents == []
