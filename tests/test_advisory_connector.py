"""Unit tests for GitHub Advisory connector, normalization, error handling, and caching."""

import json
import os
import pytest
from src.advisory_connector import GitHubAdvisoryConnector, normalize_github_advisory
from src.schemas import SecurityAdvisory


def test_advisory_normalization():
    """Verify normalization of GitHub API advisory payload."""
    raw = {
        "ghsa_id": "GHSA-558c-9hv2-4prj",
        "cve_id": "CVE-2026-113721",
        "summary": "virtualenv link following",
        "description": "Generated activation files can follow links.",
        "severity": "MEDIUM",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "virtualenv"},
                "vulnerable_version_range": "< 21.14.9",
                "first_patched_version": "21.14.9"
            }
        ],
        "published_at": "2026-10-22T17:03:12Z",
        "html_url": "https://github.com/advisories/GHSA-558c-9hv2-4prj"
    }

    norm = normalize_github_advisory(raw, data_source="live_api")
    assert isinstance(norm, SecurityAdvisory)
    assert norm.ghsa_id == "GHSA-558c-9hv2-4prj"
    assert norm.cve_id == "CVE-2026-113721"
    assert norm.package_name == "virtualenv"
    assert norm.ecosystem == "pip"
    assert norm.vulnerable_version_range == "< 21.14.9"
    assert norm.first_patched_version == "21.14.9"
    assert norm.severity == "medium"
    assert norm.data_source == "live_api"


def test_advisory_caching_and_offline_load(tmp_path):
    """Verify writing and loading normalized advisories from disk cache."""
    cache_file = str(tmp_path / "test_cache.json")
    connector = GitHubAdvisoryConnector(cache_path=cache_file)

    adv = SecurityAdvisory(
        ghsa_id="GHSA-test-1234-abcd",
        cve_id="CVE-2026-9999",
        summary="Test advisory",
        description="Detailed description",
        severity="high",
        ecosystem="npm",
        package_name="test-pkg",
        vulnerable_version_range="< 1.0.0",
        first_patched_version="1.0.0",
        published_at="2026-10-23T00:00:00Z",
        source_url="https://github.com/advisories/GHSA-test-1234-abcd",
        data_source="live_api"
    )

    connector.cache_advisories([adv])
    assert os.path.exists(cache_file)

    loaded = connector.load_cached_advisories()
    assert len(loaded) == 1
    assert loaded[0].ghsa_id == "GHSA-test-1234-abcd"
    assert loaded[0].data_source == "local_cache"


def test_connector_offline_mode_retrieves_cache(tmp_path):
    """Verify that force_offline flag immediately uses cache without network calls."""
    cache_file = str(tmp_path / "offline_cache.json")
    connector = GitHubAdvisoryConnector(cache_path=cache_file)

    adv = SecurityAdvisory(
        ghsa_id="GHSA-offline-1234",
        cve_id=None,
        summary="Offline test",
        description="Desc",
        severity="low",
        ecosystem="pip",
        package_name="offline-pkg",
        vulnerable_version_range="< 2.0.0",
        first_patched_version="2.0.0",
        published_at="2026-10-23T00:00:00Z",
        source_url="https://github.com/advisories/GHSA-offline-1234",
        data_source="live_api"
    )
    connector.cache_advisories([adv])

    result, source, msg = connector.get_advisory(ghsa_id="GHSA-offline-1234", force_offline=True)
    assert result is not None
    assert result.ghsa_id == "GHSA-offline-1234"
    assert source == "local_cache"
    assert "offline mode" in msg


def test_connector_malformed_cache_handling(tmp_path):
    """Verify that malformed cache files do not crash the connector."""
    cache_file = str(tmp_path / "broken_cache.json")
    with open(cache_file, "w") as f:
        f.write("{corrupted json not an array...")

    connector = GitHubAdvisoryConnector(cache_path=cache_file)
    cached = connector.load_cached_advisories()
    assert cached == []


def test_connector_network_failure_falls_back_to_cache(tmp_path, monkeypatch):
    """Verify that when network fails, connector gracefully falls back to local cache."""
    cache_file = str(tmp_path / "fallback_cache.json")
    connector = GitHubAdvisoryConnector(cache_path=cache_file)

    # Seed cache
    cached_adv = SecurityAdvisory(
        ghsa_id="GHSA-cached-fallback",
        cve_id="CVE-2026-8888",
        summary="Fallback test",
        description="Desc",
        severity="medium",
        ecosystem="pip",
        package_name="fallback-lib",
        vulnerable_version_range="< 3.0.0",
        first_patched_version="3.0.0",
        published_at="2026-10-23T00:00:00Z",
        source_url="https://github.com/advisories/GHSA-cached-fallback",
        data_source="local_cache"
    )
    connector.cache_advisories([cached_adv])

    # Simulate network error in urllib.request.urlopen
    def mock_urlopen(*args, **kwargs):
        import urllib.error
        raise urllib.error.URLError("Simulated connection refused")

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    adv, source, msg = connector.get_advisory(ghsa_id="GHSA-cached-fallback", force_offline=False)
    assert adv is not None
    assert adv.ghsa_id == "GHSA-cached-fallback"
    assert source == "local_cache"
    assert "Live API unavailable" in msg
