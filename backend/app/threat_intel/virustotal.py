"""
VirusTotal v3 API client.

Fetches reputation data for URLs, file hashes, domains, and IP addresses.
We extract every meaningful field VT exposes — these signals feed both the
deterministic threat-intel score and the Claude analysis prompt.

Free-tier: 4 requests/min, 500/day.
"""

import base64
import logging
from typing import Any

import requests

from app.config.settings import settings

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = 8  # seconds — keep aggressive so a slow VT doesn't block analysis


def _headers() -> dict[str, str]:
    return {"x-apikey": settings.VIRUSTOTAL_API_KEY or ""}


def _is_configured() -> bool:
    return bool(settings.VIRUSTOTAL_API_KEY)


def _url_to_id(url: str) -> str:
    """VT v3 URL ID = base64url(url) without padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")


def _summarize_analysis(attributes: dict[str, Any]) -> dict[str, Any]:
    """Common fields across URL / file / domain / IP responses."""
    stats = attributes.get("last_analysis_stats", {}) or {}
    total = sum(stats.values()) if stats else 0

    return {
        "malicious_count": stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "harmless_count": stats.get("harmless", 0),
        "undetected_count": stats.get("undetected", 0),
        "timeout_count": stats.get("timeout", 0),
        "total_engines": total,
        "reputation": attributes.get("reputation"),
        "first_submission_date": attributes.get("first_submission_date"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "total_votes_harmless": (attributes.get("total_votes") or {}).get("harmless"),
        "total_votes_malicious": (attributes.get("total_votes") or {}).get("malicious"),
    }


def _get(endpoint: str) -> dict[str, Any] | None:
    """Make a GET request to VT, return JSON or None on error/not-found."""
    if not _is_configured():
        logger.warning("VirusTotal API key not configured — skipping lookup")
        return None

    url = f"{VT_API_BASE}/{endpoint.lstrip('/')}"
    try:
        response = requests.get(url, headers=_headers(), timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as exc:
        logger.warning("VirusTotal request failed for %s: %s", endpoint, exc)
        return None

    if response.status_code == 404:
        return None  # not in VT yet — caller decides what to do
    if response.status_code == 429:
        logger.warning("VirusTotal rate limit hit on %s", endpoint)
        return None
    if response.status_code != 200:
        logger.warning(
            "VirusTotal returned %s on %s: %s",
            response.status_code,
            endpoint,
            response.text[:200],
        )
        return None

    try:
        return response.json()
    except ValueError:
        logger.warning("VirusTotal returned invalid JSON for %s", endpoint)
        return None


def check_url(url: str) -> dict[str, Any] | None:
    """
    Look up a URL's reputation.

    Returns parsed VT data or None if unavailable / unknown.
    """
    if not url:
        return None

    raw = _get(f"urls/{_url_to_id(url)}")
    if not raw:
        return None

    attributes = (raw.get("data") or {}).get("attributes", {}) or {}

    result = {
        "kind": "url",
        "url": url,
        **_summarize_analysis(attributes),
        "title": attributes.get("title"),
        "last_final_url": attributes.get("last_final_url"),
        "threat_names": attributes.get("threat_names") or [],
        "categories": attributes.get("categories") or {},
        "tags": attributes.get("tags") or [],
    }
    result["is_malicious"] = result["malicious_count"] > 0
    return result


def check_file_hash(file_hash: str) -> dict[str, Any] | None:
    """
    Look up a file by its hash (MD5 / SHA-1 / SHA-256).

    Returns parsed VT data or None if unavailable / unknown.
    """
    if not file_hash:
        return None

    raw = _get(f"files/{file_hash}")
    if not raw:
        return None

    attributes = (raw.get("data") or {}).get("attributes", {}) or {}

    result = {
        "kind": "file",
        "sha256": attributes.get("sha256"),
        "md5": attributes.get("md5"),
        "sha1": attributes.get("sha1"),
        **_summarize_analysis(attributes),
        "meaningful_name": attributes.get("meaningful_name"),
        "type_description": attributes.get("type_description"),
        "type_tag": attributes.get("type_tag"),
        "size": attributes.get("size"),
        "names": attributes.get("names") or [],
        "tags": attributes.get("tags") or [],
        "popular_threat_classification": attributes.get("popular_threat_classification") or {},
        "sandbox_verdicts": attributes.get("sandbox_verdicts") or {},
    }
    result["is_malicious"] = result["malicious_count"] > 0
    return result


def check_domain(domain: str) -> dict[str, Any] | None:
    """Look up a domain's reputation."""
    if not domain:
        return None

    raw = _get(f"domains/{domain}")
    if not raw:
        return None

    attributes = (raw.get("data") or {}).get("attributes", {}) or {}

    result = {
        "kind": "domain",
        "domain": domain,
        **_summarize_analysis(attributes),
        "categories": attributes.get("categories") or {},
        "creation_date": attributes.get("creation_date"),
        "last_dns_records": attributes.get("last_dns_records") or [],
        "registrar": attributes.get("registrar"),
        "tags": attributes.get("tags") or [],
    }
    result["is_malicious"] = result["malicious_count"] > 0
    return result


def check_ip(ip: str) -> dict[str, Any] | None:
    """Look up an IP address's reputation."""
    if not ip:
        return None

    raw = _get(f"ip_addresses/{ip}")
    if not raw:
        return None

    attributes = (raw.get("data") or {}).get("attributes", {}) or {}

    result = {
        "kind": "ip",
        "ip": ip,
        **_summarize_analysis(attributes),
        "country": attributes.get("country"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "network": attributes.get("network"),
        "tags": attributes.get("tags") or [],
    }
    result["is_malicious"] = result["malicious_count"] > 0
    return result


def is_proven_malicious(vt_result: dict[str, Any] | None) -> bool:
    """
    Did enough engines flag this entity to call it 'proven malicious'?
    Threshold is configurable via VT_PROVEN_MALICIOUS_ENGINES.
    """
    if not vt_result:
        return False
    return vt_result.get("malicious_count", 0) >= settings.VT_PROVEN_MALICIOUS_ENGINES
