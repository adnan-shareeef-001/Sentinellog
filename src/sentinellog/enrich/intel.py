"""Threat intelligence indicator lookup engine supporting exact IP and CIDR matching."""

import ipaddress
from pathlib import Path
from typing import Any


class ThreatIntelFeed:
    """Manages threat intelligence indicators and provides fast IP/CIDR lookup."""

    def __init__(self) -> None:
        self.exact_ips: set[str] = set()
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    def load_file(self, path: Path | str) -> int:
        """Load IP blocklist indicators from a file. Returns number of indicators added."""
        feed_path = Path(path)
        if not feed_path.is_file():
            return 0

        count = 0
        content = feed_path.read_text(encoding="utf-8")
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if "/" in stripped:
                try:
                    net = ipaddress.ip_network(stripped, strict=False)
                    self.networks.append(net)
                    count += 1
                except ValueError:
                    continue
            else:
                try:
                    ip = ipaddress.ip_address(stripped)
                    self.exact_ips.add(str(ip))
                    count += 1
                except ValueError:
                    continue

        return count

    def load_dir(self, dir_path: Path | str) -> int:
        """Load all .txt files from a threat intelligence directory."""
        directory = Path(dir_path)
        if not directory.is_dir():
            return 0

        total = 0
        for entry in directory.glob("*.txt"):
            total += self.load_file(entry)
        return total

    def is_blocked(self, ip_str: str | None) -> bool:
        """Check if an IP matches an exact blocklist entry or CIDR network range."""
        if not ip_str:
            return False

        clean = ip_str.strip()
        if not clean:
            return False

        if clean in self.exact_ips:
            return True

        try:
            ip = ipaddress.ip_address(clean)
        except ValueError:
            return False

        for net in self.networks:
            if ip in net:
                return True

        return False

    def lookup(self, ip_str: str | None) -> dict[str, Any] | None:
        """Return threat intelligence metadata if the IP is blocked, else None."""
        if not self.is_blocked(ip_str):
            return None

        clean = str(ip_str).strip()
        matched_type = "exact_ip" if clean in self.exact_ips else "cidr_range"
        return {
            "indicator": clean,
            "category": "malicious_ip",
            "matched_by": matched_type,
            "confidence": 95,
        }


_GLOBAL_FEED: ThreatIntelFeed | None = None


def get_threat_intel_feed(feed_dir: Path | str = "data/threat_intel") -> ThreatIntelFeed:
    """Retrieve or initialize the global threat intelligence feed."""
    global _GLOBAL_FEED
    if _GLOBAL_FEED is None:
        feed = ThreatIntelFeed()
        p = Path(feed_dir)
        if p.is_dir():
            feed.load_dir(p)
        elif p.is_file():
            feed.load_file(p)
        _GLOBAL_FEED = feed
    return _GLOBAL_FEED
