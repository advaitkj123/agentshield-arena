"""GitHub Global Security Advisories REST API connector and local caching.

Fetches reviewed public advisories using Python standard library urllib and json.
Normalizes data into SecurityAdvisory entities and maintains an offline cache.
Zero paid tokens, zero external library dependencies.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from src.schemas import SecurityAdvisory


GITHUB_ADVISORIES_API = "https://api.github.com/advisories"
DEFAULT_CACHE_PATH = "data/cached_advisories.json"


def normalize_github_advisory(raw: Dict[str, Any], data_source: str = "live_api") -> SecurityAdvisory:
    """Normalize a raw GitHub Advisory JSON dictionary into SecurityAdvisory schema."""
    ghsa_id = raw.get("ghsa_id", "GHSA-UNKNOWN")
    cve_id = raw.get("cve_id")
    summary = raw.get("summary", "No summary provided.")
    description = raw.get("description", "No description provided.")
    severity = str(raw.get("severity", "medium")).lower()

    # Extract vulnerability package specifics
    vulnerabilities = raw.get("vulnerabilities", [])
    ecosystem = raw.get("ecosystem", "unknown")
    package_name = raw.get("package_name", "unknown")
    vulnerable_range = raw.get("vulnerable_version_range", "unknown")
    patched_version = raw.get("first_patched_version")

    if vulnerabilities and isinstance(vulnerabilities, list) and len(vulnerabilities) > 0:
        v0 = vulnerabilities[0]
        if isinstance(v0, dict):
            pkg = v0.get("package", {})
            if isinstance(pkg, dict):
                ecosystem = pkg.get("ecosystem", ecosystem) or ecosystem
                package_name = pkg.get("name", package_name) or package_name
            vulnerable_range = v0.get("vulnerable_version_range", vulnerable_range) or vulnerable_range
            patched_version = v0.get("first_patched_version", patched_version)

    # Fallback to top-level 'package' dict if vulnerabilities list did not populate package details
    if (package_name == "unknown" or not package_name) and "package" in raw and isinstance(raw["package"], dict):
        package_name = raw["package"].get("name", package_name) or package_name
        ecosystem = raw["package"].get("ecosystem", ecosystem) or ecosystem

    # Normalize patched_version if wrapped in dict or list
    if isinstance(patched_version, dict):
        patched_version = patched_version.get("identifier")
    elif isinstance(patched_version, list) and patched_version:
        patched_version = str(patched_version[0])

    # Fallback heuristic: parse package name from summary if still unknown and prefixed with 'name: '
    if (package_name == "unknown" or not package_name) and summary and ":" in summary:
        candidate = summary.split(":")[0].strip()
        if " " not in candidate and len(candidate) < 50:
            package_name = candidate.lower()

    published_at = raw.get("published_at", "")
    source_url = raw.get("html_url", f"https://github.com/advisories/{ghsa_id}")

    return SecurityAdvisory(
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        summary=summary,
        description=description,
        severity=severity,
        ecosystem=ecosystem,
        package_name=package_name,
        vulnerable_version_range=vulnerable_range,
        first_patched_version=patched_version,
        published_at=published_at,
        source_url=source_url,
        data_source=data_source
    )


class GitHubAdvisoryConnector:
    """Standard-library connector for GitHub Security Advisories."""

    def __init__(self, cache_path: str = DEFAULT_CACHE_PATH, timeout: int = 5):
        self.cache_path = cache_path
        self.timeout = timeout

    def fetch_live_advisories(
        self,
        ecosystem: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 5
    ) -> Tuple[List[SecurityAdvisory], Optional[str]]:
        """Fetch advisories from GitHub REST API.

        Returns (list_of_advisories, error_message).
        """
        params = {"per_page": min(limit, 20)}
        if ecosystem:
            params["ecosystem"] = ecosystem
        if severity:
            params["severity"] = severity

        query_str = urllib.parse.urlencode(params)
        url = f"{GITHUB_ADVISORIES_API}?{query_str}"

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "AgentShield-Arena-Security-Audit/1.0",
                "Accept": "application/vnd.github+json"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if response.status != 200:
                    return [], f"GitHub API responded with HTTP {response.status}"
                content = response.read().decode("utf-8")
                raw_data = json.loads(content)

            if not isinstance(raw_data, list):
                return [], "Unexpected response format: expected JSON array"

            advisories = [normalize_github_advisory(d, data_source="live_api") for d in raw_data]
            return advisories, None

        except urllib.error.HTTPError as e:
            if e.code == 403:
                return [], f"GitHub API rate limit exceeded or access forbidden (HTTP 403)"
            return [], f"HTTP error querying GitHub API: {e.code} {e.reason}"
        except urllib.error.URLError as e:
            return [], f"Network connection error contacting GitHub API: {e.reason}"
        except TimeoutError:
            return [], f"Connection timed out after {self.timeout}s querying GitHub API"
        except json.JSONDecodeError:
            return [], "Malformed JSON received from GitHub API"
        except Exception as e:
            return [], f"Unexpected error querying GitHub API: {str(e)}"

    def cache_advisories(self, advisories: List[SecurityAdvisory]) -> None:
        """Write normalized advisories to local disk cache."""
        os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
        data = [a.to_dict() for a in advisories]
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_cached_advisories(self) -> List[SecurityAdvisory]:
        """Load normalized advisories from local disk cache."""
        if not os.path.exists(self.cache_path):
            return []
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            advisories = []
            for d in data:
                d["data_source"] = "local_cache"
                advisories.append(SecurityAdvisory(**d))
            return advisories
        except Exception:
            return []

    def get_advisory(
        self,
        ghsa_id: Optional[str] = None,
        force_offline: bool = False
    ) -> Tuple[Optional[SecurityAdvisory], str, Optional[str]]:
        """Retrieve an advisory by ID or first available, trying live API then local cache.

        Returns (advisory_or_none, data_source_label, status_message).
        """
        # If offline forced, go directly to cache
        if force_offline:
            cached = self.load_cached_advisories()
            if not cached:
                return None, "none", f"Offline mode requested but cache file '{self.cache_path}' is empty or missing."
            match = next((a for a in cached if a.ghsa_id == ghsa_id), cached[0]) if ghsa_id else cached[0]
            return match, "local_cache", "Loaded advisory from local verified cache (offline mode)."

        # Try live API
        live_list, err = self.fetch_live_advisories(limit=10)
        if live_list:
            # Cache the newly fetched advisories
            self.cache_advisories(live_list)
            match = next((a for a in live_list if a.ghsa_id == ghsa_id), live_list[0]) if ghsa_id else live_list[0]
            return match, "live_api", "Fetched advisory directly from live GitHub REST API."

        # If live failed, fall back to cache with clear notification
        cached = self.load_cached_advisories()
        if cached:
            match = next((a for a in cached if a.ghsa_id == ghsa_id), cached[0]) if ghsa_id else cached[0]
            return match, "local_cache", f"Live API unavailable ({err}). Loaded advisory from verified local cache."

        return None, "none", f"Unable to fetch advisory: live API failed ({err}) and local cache is missing."
