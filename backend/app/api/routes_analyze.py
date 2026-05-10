"""
Main analysis endpoint.

Flow:
  1. Receive a parsed email from the Apps Script add-on.
  2. Extract deterministic features.
  3. Apply sender-history-driven flags (no I/O — provided by Code.gs).
  4. Gather threat intelligence in parallel (VT + AbuseIPDB + URL expansion).
     Each call has its own timeout; the orchestrator caps total wall-clock.
  5. Use the gathered intel to set late-binding flags
     (`domain_recently_registered`, `recently_seen_attachment`).
  6. Call Claude with the full email + features + threat-intel context.
  7. Run the weighted scoring engine to produce the final RiskResult.
  8. Generate the deterministic user_explanation as a backup narrative
     (the frontend prefers Claude's structured fields when available).
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.ai.claude_client import analyze_with_claude
from app.explanation.generator import generate_user_explanation
from app.scoring.engine import ScoringEngine
from app.scoring.feature_extractor import extract_features
from app.scoring.models import (
    AbuseIPDBResult,
    EmailFeatures,
    ParsedEmail,
    RiskResult,
    SafeBrowsingResult,
    ThreatIntelData,
    UrlExpansionResult,
    UrlhausResult,
    UrlInfo,
    VirusTotalResult,
)
from app.threat_intel import (
    abuseipdb,
    safe_browsing,
    url_expander,
    urlhaus,
    virustotal,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["analysis"])


# Caps to keep total request latency bounded
MAX_URLS_TO_SCAN = 5
MAX_ATTACHMENT_HASHES_TO_SCAN = 3

# Domain registered within this many days = "recently registered"
DOMAIN_RECENTLY_REGISTERED_DAYS = 30
# File first seen within this many hours = "recently seen attachment"
ATTACHMENT_RECENTLY_SEEN_HOURS = 72

# Sender-spam-history thresholds. Either condition triggers the flag.
SENDER_SPAM_HISTORY_MIN_COUNT = 3       # absolute count of prior spam/trash threads
SENDER_SPAM_HISTORY_MIN_RATIO = 0.30    # >= 30% of all sender's threads are spam/trash

# Shorteners we'll attempt to expand (server-side HEAD request)
_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "lnkd.in",
}


class AnalyzeParsedEmailRequest(BaseModel):
    email: ParsedEmail


# ============================================================
# Helpers
# ============================================================

def _epoch_to_age_days(epoch: int | None) -> int | None:
    if not epoch:
        return None
    try:
        ts = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None
    return (datetime.now(tz=timezone.utc) - ts).days


def _epoch_to_age_hours(epoch: int | None) -> float | None:
    if not epoch:
        return None
    try:
        ts = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None
    return (datetime.now(tz=timezone.utc) - ts).total_seconds() / 3600.0


def _is_shortener(url_info: UrlInfo) -> bool:
    return (url_info.domain or "").lower() in _SHORTENER_DOMAINS


def _safely_build_vt_result(raw: dict[str, Any] | None) -> VirusTotalResult | None:
    """
    Coerce a normalized dict from app/threat_intel/virustotal.py into a
    VirusTotalResult. The VT client returns slightly different shapes per
    entity kind; we unify them onto the model's "target" field.
    """
    if not raw:
        return None
    try:
        kind = raw.get("kind", "url")
        target = (
            raw.get("url")
            or raw.get("sha256")
            or raw.get("domain")
            or raw.get("ip")
            or ""
        )
        # Strip identifier-y fields the model doesn't expect by name
        clean = {k: v for k, v in raw.items() if k not in {"url", "domain", "ip"}}
        clean["kind"] = kind
        clean["target"] = target
        return VirusTotalResult(**clean)
    except Exception as exc:
        logger.warning("Failed to coerce VT result (%s): %s", raw.get("kind"), exc)
        return None


# ============================================================
# Threat Intelligence Orchestration
# ============================================================

def _gather_threat_intel(email: ParsedEmail) -> ThreatIntelData:
    """
    Run all threat-intel lookups in parallel via a ThreadPoolExecutor.
    Each upstream module enforces its own per-call timeout; we additionally
    cap total wall-clock here so a slow upstream can't hang the request.
    """
    start = time.monotonic()

    sender_ip = abuseipdb.extract_sender_ip_from_headers(
        authentication_results=email.authentication_results,
    )

    urls_to_scan = list(email.urls[:MAX_URLS_TO_SCAN])
    hashes_to_scan = [
        a.sha256
        for a in email.attachments[:MAX_ATTACHMENT_HASHES_TO_SCAN]
        if a.sha256
    ]
    urls_to_expand = [u for u in urls_to_scan if _is_shortener(u)]

    url_results: list[VirusTotalResult] = []
    file_results: list[VirusTotalResult] = []
    domain_results: list[VirusTotalResult] = []
    ip_results: list[VirusTotalResult] = []
    abuseipdb_result: AbuseIPDBResult | None = None
    url_expansions: list[UrlExpansionResult] = []
    safe_browsing_results: list[SafeBrowsingResult] = []
    urlhaus_results: list[UrlhausResult] = []

    with ThreadPoolExecutor(max_workers=12) as ex:
        futures: dict[Any, tuple[str, Any]] = {}

        for u in urls_to_scan:
            futures[ex.submit(virustotal.check_url, u.url)] = ("vt_url", u.url)
            # Three additional URL reputation sources, all run in parallel.
            futures[ex.submit(safe_browsing.check_url, u.url)] = ("gsb_url", u.url)
            futures[ex.submit(urlhaus.check_url, u.url)] = ("urlhaus_url", u.url)

        for h in hashes_to_scan:
            futures[ex.submit(virustotal.check_file_hash, h)] = ("vt_file", h)

        if email.from_domain:
            futures[ex.submit(virustotal.check_domain, email.from_domain)] = (
                "vt_domain", email.from_domain,
            )

        if sender_ip:
            futures[ex.submit(virustotal.check_ip, sender_ip)] = ("vt_ip", sender_ip)
            futures[ex.submit(abuseipdb.check_ip, sender_ip)] = ("abuse_ip", sender_ip)

        for u in urls_to_expand:
            futures[ex.submit(url_expander.expand_url, u.url)] = ("expand_url", u.url)

        try:
            for fut in as_completed(futures, timeout=15):
                kind, target = futures[fut]
                try:
                    result = fut.result()
                except Exception as exc:
                    logger.warning(
                        "Threat-intel call failed (%s/%s): %s", kind, target, exc
                    )
                    continue

                if result is None:
                    continue

                if kind == "vt_url":
                    vt = _safely_build_vt_result(result)
                    if vt:
                        url_results.append(vt)
                elif kind == "vt_file":
                    vt = _safely_build_vt_result(result)
                    if vt:
                        file_results.append(vt)
                elif kind == "vt_domain":
                    vt = _safely_build_vt_result(result)
                    if vt:
                        domain_results.append(vt)
                elif kind == "vt_ip":
                    vt = _safely_build_vt_result(result)
                    if vt:
                        ip_results.append(vt)
                elif kind == "abuse_ip":
                    try:
                        abuseipdb_result = AbuseIPDBResult(**result)
                    except Exception as exc:
                        logger.warning("Failed to coerce AbuseIPDB result: %s", exc)
                elif kind == "expand_url":
                    try:
                        url_expansions.append(UrlExpansionResult(**result))
                    except Exception as exc:
                        logger.warning("Failed to coerce URL expansion: %s", exc)
                elif kind == "gsb_url":
                    try:
                        safe_browsing_results.append(SafeBrowsingResult(**result))
                    except Exception as exc:
                        logger.warning("Failed to coerce Safe Browsing result: %s", exc)
                elif kind == "urlhaus_url":
                    try:
                        urlhaus_results.append(UrlhausResult(**result))
                    except Exception as exc:
                        logger.warning("Failed to coerce URLhaus result: %s", exc)
        except TimeoutError:
            logger.warning("Threat-intel orchestration hit overall timeout")

    elapsed = time.monotonic() - start
    logger.info("Threat-intel gather completed in %.2fs", elapsed)

    return ThreatIntelData(
        url_results=url_results,
        file_results=file_results,
        domain_results=domain_results,
        ip_results=ip_results,
        abuseipdb_result=abuseipdb_result,
        url_expansions=url_expansions,
        sender_ip=sender_ip,
        safe_browsing_results=safe_browsing_results,
        urlhaus_results=urlhaus_results,
    )


# ============================================================
# Late-binding feature enrichment
# ============================================================

def _enrich_features_from_threat_intel(
    features: EmailFeatures,
    email: ParsedEmail,
    threat_intel: ThreatIntelData,
) -> None:
    """
    Set feature flags that can only be computed once threat-intel data is
    in hand: domain-recently-registered, recently-seen-attachment.
    Mutates `features` in place.
    """
    sender_domain = (email.from_domain or "").lower()
    for r in threat_intel.domain_results:
        if r.target.lower() == sender_domain:
            age_days = _epoch_to_age_days(r.creation_date)
            if age_days is not None and age_days <= DOMAIN_RECENTLY_REGISTERED_DAYS:
                features.domain_recently_registered = True
            break

    for r in threat_intel.file_results:
        age_hours = _epoch_to_age_hours(r.first_submission_date)
        if age_hours is not None and age_hours <= ATTACHMENT_RECENTLY_SEEN_HOURS:
            features.recently_seen_attachment = True
            break


def _enrich_features_from_sender_history(
    features: EmailFeatures,
    email: ParsedEmail,
) -> None:
    """
    Set feature flags from the SenderHistory provided by Code.gs.
    All flags default to False if no history is provided.
    """
    h = email.sender_history
    if not h or not h.available:
        return

    if h.is_first_time_sender:
        features.is_first_time_sender = True
    if h.has_user_replied:
        features.has_user_replied_to_sender = True

    # Sender-spam-history: either an absolute count threshold OR a ratio
    # of (spam+trash) / total prior threads.
    spam_or_trash = (h.spam_count or 0) + (h.trash_count or 0)
    if spam_or_trash >= SENDER_SPAM_HISTORY_MIN_COUNT:
        features.sender_has_spam_history = True
    elif h.total_threads > 0:
        ratio = spam_or_trash / max(h.total_threads, 1)
        if ratio >= SENDER_SPAM_HISTORY_MIN_RATIO and spam_or_trash >= 1:
            features.sender_has_spam_history = True


# ============================================================
# Main endpoint
# ============================================================

@router.post("/analyze-email", response_model=RiskResult)
def analyze_email(request: AnalyzeParsedEmailRequest) -> RiskResult:
    email = request.email

    features = extract_features(email)
    _enrich_features_from_sender_history(features, email)

    threat_intel = _gather_threat_intel(email)
    _enrich_features_from_threat_intel(features, email, threat_intel)

    claude_analysis = analyze_with_claude(email, features, threat_intel)

    result = ScoringEngine().calculate(
        features=features,
        threat_intel=threat_intel,
        claude_analysis=claude_analysis,
    )

    # Backup narrative for clients that don't render claude_analysis directly.
    result.user_explanation = generate_user_explanation(result)

    return result
