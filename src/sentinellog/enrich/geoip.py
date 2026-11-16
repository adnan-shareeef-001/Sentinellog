"""GeoIP geolocation enrichment with offline MaxMind fallback."""

import importlib
import ipaddress
from pathlib import Path
from typing import Any


class GeoIPEnricher:
    """Provides IP geolocation lookups with safe offline fallback."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.reader = None
        if db_path:
            p = Path(db_path)
            if p.is_file():
                try:
                    mod = importlib.import_module("geoip2.database")
                    self.reader = mod.Reader(str(p))
                except Exception:
                    self.reader = None

    def lookup(self, ip_str: str | None) -> dict[str, Any]:
        """Resolve geographic metadata for an IP address safely."""
        fallback = {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
        }
        if not ip_str:
            return fallback

        clean = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(clean)
            if ip_obj.is_private or ip_obj.is_loopback:
                return {
                    "country": "Private",
                    "city": "Internal",
                    "latitude": None,
                    "longitude": None,
                }
        except ValueError:
            return fallback

        if self.reader:
            try:
                response = self.reader.city(clean)
                return {
                    "country": response.country.name or "Unknown",
                    "city": response.city.name or "Unknown",
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                }
            except Exception:
                return fallback

        return fallback
