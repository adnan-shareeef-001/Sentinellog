"""Unit tests for the asset inventory and criticality engine."""

from pathlib import Path

from sentinellog.enrich.assets import AssetInventory


def test_asset_inventory_loading_and_lookup(tmp_path: Path) -> None:
    asset_file = tmp_path / "assets.yaml"
    asset_file.write_text(
        "srv-prod-01:\n"
        "  role: web_server\n"
        "  criticality: high\n"
        "  department: engineering\n"
        "db-primary:\n"
        "  role: database\n"
        "  criticality: critical\n",
        encoding="utf-8",
    )

    inv = AssetInventory()
    count = inv.load(asset_file)
    assert count == 2

    # Case-insensitive lookup
    asset = inv.get_asset("SRV-PROD-01")
    assert asset is not None
    assert asset.name == "srv-prod-01"
    assert asset.criticality == "high"
    assert asset.role == "web_server"

    assert inv.get_criticality("db-primary") == "critical"
    # Unknown asset defaults to low
    assert inv.get_criticality("unknown-host") == "low"
    assert inv.get_criticality(None) == "low"
