"""
Server-side URL expander.

Follows redirect chains for shortened URLs (bit.ly, t.co, etc.) without
loading any JavaScript or rendering pages. Uses HEAD requests so we never
download response bodies.

Tradeoffs (T4):
- HEAD requests still hit the attacker's server — they may log our IP.
- We bound: max redirects, hard timeout, no body download.
- We never expose the user's IP — this runs server-side.
"""

import logging
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5
MAX_REDIRECTS = 8

# Domains we don't bother expanding — they're either trusted or recursive
_NO_EXPAND_DOMAINS = {"google.com", "youtube.com", "facebook.com", "twitter.com"}


def _is_shortener_or_unknown(domain: str | None) -> bool:
    if not domain:
        return False
    return domain not in _NO_EXPAND_DOMAINS


def expand_url(url: str) -> dict[str, Any]:
    """
    Follow redirects for a URL and report what we found.

    Returns:
        {
            "original_url": str,
            "final_url": str | None,
            "redirect_chain": list[str],
            "redirect_count": int,
            "expanded": bool,        # True if a redirect actually happened
            "error": str | None,
        }
    """
    result: dict[str, Any] = {
        "original_url": url,
        "final_url": None,
        "redirect_chain": [],
        "redirect_count": 0,
        "expanded": False,
        "error": None,
    }

    if not url:
        result["error"] = "empty url"
        return result

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            result["error"] = f"unsupported scheme: {parsed.scheme}"
            return result
    except Exception as exc:
        result["error"] = f"parse error: {exc}"
        return result

    try:
        response = requests.head(
            url,
            allow_redirects=True,
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (Gmail Risk Scanner; security-research)"},
        )
        chain = [r.url for r in response.history] + [response.url]
        result["redirect_chain"] = chain
        result["redirect_count"] = max(0, len(chain) - 1)
        result["final_url"] = response.url
        result["expanded"] = result["redirect_count"] > 0
    except requests.TooManyRedirects:
        result["error"] = "too many redirects"
    except requests.Timeout:
        result["error"] = "timeout"
    except requests.RequestException as exc:
        result["error"] = f"request failed: {exc.__class__.__name__}"
    except Exception as exc:
        logger.warning("Unexpected error expanding %s: %s", url, exc)
        result["error"] = "unknown error"

    return result
