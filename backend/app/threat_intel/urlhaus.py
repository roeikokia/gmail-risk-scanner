"""
URLhaus (abuse.ch) client.

URLhaus is a free, community-driven database of URLs known to host malware
payloads. It complements VirusTotal by focusing specifically on malware
distribution URLs — often catching newly-observed payload-hosting domains
within hours of their appearance.

Free public API. No authentication required. Sub-second responses.

Endpoint: https://urlhaus-api.abuse.ch/v1/url/
Docs:     https://urlhaus-api.abuse.ch/
"""

import logging
from typing import Any

import requests

from app.config.settings import settings

logger = logging.getLogger(__name__)

URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
DEFAULT_TIMEOUT = 5  # seconds


def check_url(url: str) -> dict[str, Any] | None:
    """
    Look up a URL in URLhaus.

    Returns:
        - None if the URL is not in URLhaus (or on error / timeout).
        - A normalized dict matching UrlhausResult shape if it IS in the database.
    """
    if not url:
        return None
    if not settings.URLHAUS_API_KEY:
        # URLhaus now requires an Auth-Key for all queries — fail-open silently
        # if the key isn't configured (e.g. dev environment without registration).
        return None

    headers = {
        "User-Agent": "Gmail-Risk-Scanner/1.0",
        "Auth-Key": settings.URLHAUS_API_KEY,
    }

    try:
        response = requests.post(
            URLHAUS_ENDPOINT,
            data={"url": url},
            timeout=DEFAULT_TIMEOUT,
            headers=headers,
        )
    except requests.RequestException as exc:
        logger.warning("URLhaus request failed for %s: %s", url, exc)
        return None

    if response.status_code != 200:
        logger.warning(
            "URLhaus returned %s on %s: %s",
            response.status_code, url, response.text[:200],
        )
        return None

    try:
        payload = response.json()
    except ValueError:
        logger.warning("URLhaus returned invalid JSON for %s", url)
        return None

    # URLhaus returns query_status:
    #   "ok"          → URL is in the database (malicious)
    #   "no_results"  → URL not found (not malicious per URLhaus)
    #   "invalid_url" → URL was malformed
    status = payload.get("query_status", "")
    if status != "ok":
        return {
            "url": url,
            "in_database": False,
        }

    return {
        "url": url,
        "in_database": True,
        "threat": payload.get("threat"),
        "tags": payload.get("tags") or [],
        "url_status": payload.get("url_status"),
        "date_added": payload.get("date_added"),
        "reporter": payload.get("reporter"),
    }


def is_in_database(result: dict[str, Any] | None) -> bool:
    return bool(result and result.get("in_database"))
