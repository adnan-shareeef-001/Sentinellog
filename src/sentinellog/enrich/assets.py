"""Asset inventory and criticality lookup."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class AssetMetadata:
    """Metadata representing an organizational IT asset."""

    name: str
    role: str = "server"
    criticality: str = "low"
    department: str | None = None
    environment: str | None = None


class AssetInventory:
    """In-memory inventory mapping hostnames and IPs to asset metadata."""

    def __init__(self) -> None:
        self.assets: dict[str, AssetMetadata] = {}

    def load(self, path: Path | str) -> int:
        """Load asset mapping from YAML configuration file."""
        config_path = Path(path)
        if not config_path.is_file():
            return 0

        raw_content = config_path.read_text(encoding="utf-8")
        parsed = yaml.safe_load(raw_content)
        if not isinstance(parsed, dict):
            return 0

        count = 0
        for name, details in parsed.items():
            if isinstance(details, dict):
                meta = AssetMetadata(
                    name=str(name),
                    role=str(details.get("role", "server")),
                    criticality=str(details.get("criticality", "low")).lower(),
                    department=details.get("department"),
                    environment=details.get("environment"),
                )
            else:
                meta = AssetMetadata(name=str(name))
            self.assets[str(name).lower()] = meta
            count += 1

        return count

    def get_asset(self, key: str | None) -> AssetMetadata | None:
        """Look up asset metadata by hostname or IP (case-insensitive)."""
        if not key:
            return None
        return self.assets.get(str(key).strip().lower())

    def get_criticality(self, key: str | None) -> str:
        """Return criticality string ('critical', 'high', 'medium', 'low')."""
        asset = self.get_asset(key)
        if asset:
            return asset.criticality
        return "low"

    def to_dict(self) -> dict[str, Any]:
        """Serialize inventory to dictionary."""
        return {
            name: {
                "role": a.role,
                "criticality": a.criticality,
                "department": a.department,
                "environment": a.environment,
            }
            for name, a in self.assets.items()
        }


_GLOBAL_ASSETS: AssetInventory | None = None


def get_asset_inventory(config_path: Path | str = "config/assets.yaml") -> AssetInventory:
    """Retrieve or initialize the global asset inventory."""
    global _GLOBAL_ASSETS
    if _GLOBAL_ASSETS is None:
        inventory = AssetInventory()
        p = Path(config_path)
        if p.is_file():
            inventory.load(p)
        _GLOBAL_ASSETS = inventory
    return _GLOBAL_ASSETS
