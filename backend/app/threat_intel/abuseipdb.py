"""
AbuseIPDB API v2 client.

Looks up the reputation of an IP address — critically, the sending IP
of an email — to surface known abusers, spammers, and brute-forcers.

Free-tier: 1,000 lookups/day.
"""

import logging
import re
from typing import Any

import requests

from app.config.settings import settings

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
DEFAULT_TIMEOUT = 6  # seconds

# IPv4 (covers 99% of email headers we'll see in demos)
IPV4_REGEX = re.compile(r"\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\b")

# Private / reserved ranges — don't bother looking these up
_PRIVATE_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "0.",
    "169.254.",
    "255.",
)


def _is_configured() -> bool:
    return bool(settings.ABUSEIPDB_API_KEY)


def _is_routable(ip: str) -> bool:
    if not ip:
        return False
    return not ip.startswith(_PRIVATE_PREFIXES)


def extract_sender_ip_from_headers(
    authentication_results: str | None = None,
    received_headers: list[str] | None = None,
    raw_headers: str | None = None,
) -> str | None:
    """
    Best-effort sender IP extraction from email headers.

    Strategy:
    1. Try Authentication-Results header (often contains the relay IP).
    2. Fall back to Received-header chain (originating server).
    3. Reject private/reserved ranges (those are local hops, not sender).
    """
    candidates: list[str] = []

    if authentication_results:
        candidates.extend(IPV4_REGEX.findall(authentication_results))

    if received_headers:
        for header in received_headers:
            candidates.extend(IPV4_REGEX.findall(header))

    if not candidates and raw_headers:
        candidates.extend(IPV4_REGEX.findall(raw_headers))

    for ip in candidates:
        if _is_routable(ip):
            return ip
    return None


def check_ip(ip: str, max_age_days: int = 90) -> dict[str, Any] | None:
    """
    Query AbuseIPDB for an IP address.

    Returns a parsed reputation dict or None on error / unconfigured / private IP.
    """
    if not ip or not _is_routable(ip):
        return None

    if not _is_configured():
        logger.warning("AbuseIPDB API key not configured — skipping lookup")
        return None

    try:
        response = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={
                "Key": settings.ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": max_age_days,
                "verbose": "",
            },
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        logger.warning("AbuseIPDB request failed for %s: %s", ip, exc)
        return None

    if response.status_code == 429:
        logger.warning("AbuseIPDB rate limit hit on %s", ip)
        return None
    if response.status_code != 200:
        logger.warning(
            "AbuseIPDB returned %s on %s: %s",
            response.status_code,
            ip,
            response.text[:200],
        )
        return None

    try:
        payload = response.json()
    except ValueError:
        return None

    data = (payload.get("data") or {})
    reports = data.get("reports") or []

    return {
        "ip": data.get("ipAddress") or ip,
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "country_code": data.get("countryCode"),
        "country_name": data.get("countryName"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames") or [],
        "total_reports": data.get("totalReports", 0),
        "distinct_reporters": data.get("numDistinctUsers", 0),
        "last_reported_at": data.get("lastReportedAt"),
        "is_whitelisted": data.get("isWhitelisted", False),
        "is_tor": data.get("isTor", False),
        "recent_report_categories": [
            r.get("categories") for r in reports[:5] if r.get("categories")
        ],
    }


def is_proven_malicious(abuse_result: dict[str, Any] | None) -> bool:
    """
    Did AbuseIPDB confirm this IP has high abuse confidence?
    Threshold is configurable via ABUSEIPDB_PROVEN_MALICIOUS_CONFIDENCE.
    """
    if not abuse_result:
        return False
    return abuse_result.get("abuse_confidence", 0) >= settings.ABUSEIPDB_PROVEN_MALICIOUS_CONFIDENCE
