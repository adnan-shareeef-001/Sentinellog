"""Unit tests for GeoIP enrichment with offline fallback."""

from sentinellog.enrich.geoip import GeoIPEnricher


def test_geoip_enricher_private_and_fallback() -> None:
    enricher = GeoIPEnricher(db_path=None)

    # Private IP
    res_priv = enricher.lookup("10.0.0.1")
    assert res_priv["country"] == "Private"
    assert res_priv["city"] == "Internal"

    # Loopback
    res_loop = enricher.lookup("127.0.0.1")
    assert res_loop["country"] == "Private"

    # Public IP without DB returns safe fallback
    res_pub = enricher.lookup("8.8.8.8")
    assert res_pub["country"] == "Unknown"
    assert res_pub["city"] == "Unknown"

    # None or empty
    assert enricher.lookup(None)["country"] == "Unknown"
    assert enricher.lookup("")["country"] == "Unknown"
