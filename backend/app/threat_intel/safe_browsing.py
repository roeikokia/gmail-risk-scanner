"""
Google Safe Browsing v4 Lookup API client.

Safe Browsing is Google's real-time threat database — the same data used by
Chrome to show malicious-site warnings. It complements VirusTotal by often
catching newly-discovered phishing pages 1-24 hours before they propagate
to all of VT's antivirus engines.

Free tier: 10,000 requests/day. Sub-second response time.

Endpoint: https://safebrowsing.googleapis.com/v4/threatMatches:find
Docs:     https://developers.google.com/safe-browsing/v4/lookup-api

Note on v4 vs v5: v4 is officially deprecated as of late 2024 but the API
remains operational. v5 introduces hash-prefix matching for stronger privacy
but is more complex to implement. For v1 we use v4 Lookup; v5 migration is
on the v2 roadmap.
"""

import logging
from typing import Any

import requests

from app.config.settings import settings

logger = logging.getLogger(__name__)

GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
DEFAULT_TIMEOUT = 5  # seconds

# All threat types we want to check.
# https://developers.google.com/safe-browsing/v4/usage-limits#thread-types
_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",        # phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

# Platforms to check. ANY_PLATFORM is the broadest.
_PLATFORM_TYPES = ["ANY_PLATFORM"]

_THREAT_ENTRY_TYPES = ["URL"]


def _is_configured() -> bool:
    return bool(settings.GOOGLE_SAFE_BROWSING_API_KEY)


def check_url(url: str) -> dict[str, Any] | None:
    """
    Look up a URL in Google Safe Browsing.

    Returns:
        - None on missing key / error / timeout.
        - A dict matching SafeBrowsingResult shape otherwise.
          is_threat=False if URL is clean per GSB.
    """
    if not url:
        return None
    if not _is_configured():
        logger.warning("Google Safe Browsing API key not configured — skipping lookup")
        return None

    request_body = {
        "client": {
            "clientId": "gmail-risk-scanner",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": _PLATFORM_TYPES,
            "threatEntryTypes": _THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            GSB_ENDPOINT,
            params={"key": settings.GOOGLE_SAFE_BROWSING_API_KEY},
            json=request_body,
            timeout=DEFAULT_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
    except requests.RequestException as exc:
        logger.warning("Safe Browsing request failed for %s: %s", url, exc)
        return None

    if response.status_code == 429:
        logger.warning("Safe Browsing rate limit (HTTP 429)")
        return None
    if response.status_code != 200:
        logger.warning(
            "Safe Browsing returned %s on %s: %s",
            response.status_code, url, response.text[:200],
        )
        return None

    try:
        body = response.json()
    except ValueError:
        logger.warning("Safe Browsing returned invalid JSON for %s", url)
        return None

    # Empty body == URL is clean per GSB.
    matches = body.get("matches") or []
    if not matches:
        return {
            "url": url,
            "is_threat": False,
            "threat_types": [],
            "platform_types": [],
        }

    # If any match exists, the URL is flagged. Aggregate all threat types observed.
    threat_types = sorted({m.get("threatType") for m in matches if m.get("threatType")})
    platform_types = sorted({m.get("platformType") for m in matches if m.get("platformType")})

    return {
        "url": url,
        "is_threat": True,
        "threat_types": list(threat_types),
        "platform_types": list(platform_types),
    }


def is_threat(result: dict[str, Any] | None) -> bool:
    return bool(result and result.get("is_threat"))
