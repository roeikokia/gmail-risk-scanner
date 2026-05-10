"""
Weighted multi-layer scoring engine.

Each protection layer is scored independently on a 0-100 scale, then
combined via the weighted formula:

    total = 0.10·Auth + 0.25·ThreatIntel + 0.15·Identity + 0.10·Content + 0.40·Claude

Two-tier quarantine logic:
    - VT >= 5 engines OR AbuseIPDB confidence >= 75   ->  MOVE_TO_TRASH
      (proven malicious by external industry consensus)
    - composite score >= 70                            ->  MOVE_TO_SPAM
      (high-risk by our own composite judgment)
    - else                                             ->  NONE

Layer responsibilities:
    Auth:        protocol-level checks (SPF / DKIM / DMARC)
    Identity:    sender-identity consistency (display name, reply-to,
                 free-provider spoofing, suspicious-keyword domain,
                 newly-registered domain)
    ThreatIntel: external (VirusTotal + AbuseIPDB) + internal heuristics
                 about specific URLs / files
    Content:     body language patterns (urgency, financial / credential
                 requests, generic greeting)
    Claude:      AI-based judgment of intent and BEC risk
"""

from app.config.settings import settings
from app.scoring.models import (
    ClaudeAnalysis,
    EmailFeatures,
    LayerScore,
    QuarantineAction,
    RiskResult,
    RiskSignal,
    ThreatIntelData,
)


# Layer weights — sum to 1.0
LAYER_WEIGHTS: dict[str, float] = {
    "auth": 0.10,
    "threat_intel": 0.25,
    "identity": 0.15,
    "content": 0.10,
    "claude": 0.40,
}

# How aggressively VirusTotal engine counts escalate the layer score.
# 5 engines × 15 = 75 → matches the "proven malicious" quarantine threshold.
VT_URL_FILE_ENGINE_MULTIPLIER = 15

# Domain / IP signals are broader and noisier — lower escalation.
VT_DOMAIN_IP_ENGINE_MULTIPLIER = 10


def _signal(code: str, score: int, severity: str, title: str, explanation: str) -> RiskSignal:
    return RiskSignal(
        code=code,
        score=score,
        severity=severity,
        title=title,
        explanation=explanation,
    )


# ============================================================
# AUTH LAYER (10%)
# ============================================================

def _score_auth_layer(features: EmailFeatures) -> LayerScore:
    signals: list[RiskSignal] = []

    if features.spf_fail:
        signals.append(_signal(
            "SPF_FAIL", 15, "medium",
            "Sender authentication failed (SPF)",
            "The server that sent this email isn't authorized to send mail for the claimed domain. This is a strong sign of spoofing.",
        ))
    if features.dkim_fail:
        signals.append(_signal(
            "DKIM_FAIL", 15, "medium",
            "Email signature invalid (DKIM)",
            "The cryptographic signature on this email could not be verified — its contents may have been tampered with or forged.",
        ))
    if features.dmarc_fail:
        signals.append(_signal(
            "DMARC_FAIL", 20, "high",
            "Anti-spoofing check failed (DMARC)",
            "The sender domain explicitly publishes an anti-spoofing policy, and this email failed it.",
        ))

    s, d, m = features.spf_fail, features.dkim_fail, features.dmarc_fail

    if s and d and m:
        score = 100
    elif m:
        score = 80
    elif s and d:
        score = 55
    elif s or d:
        score = 30
    else:
        score = 0

    return LayerScore(
        name="auth",
        score=score,
        confidence=1.0,
        weight=LAYER_WEIGHTS["auth"],
        signals=signals,
        evidence={"spf_fail": s, "dkim_fail": d, "dmarc_fail": m},
    )


# ============================================================
# IDENTITY LAYER (15%)
# ============================================================

def _score_identity_layer(features: EmailFeatures) -> LayerScore:
    signals: list[RiskSignal] = []
    raw = 0

    if features.display_name_spoofing:
        signals.append(_signal(
            "DISPLAY_NAME_SPOOFING", 15, "high",
            "Brand impersonation in sender name",
            "The sender's display name pretends to be a known brand, but the actual email domain doesn't match that brand.",
        ))
        raw += 50

    if features.reply_to_mismatch:
        signals.append(_signal(
            "REPLY_TO_MISMATCH", 10, "medium",
            "Reply-To mismatch",
            "If you reply, your message will go to a different domain than the one shown in the sender field — a common impersonation trick.",
        ))
        raw += 30

    if features.free_provider_spoofing:
        signals.append(_signal(
            "FREE_PROVIDER_SPOOFING", 12, "medium",
            "Business role from a free email provider",
            "The sender claims to be a company role (Support, Security, IT, etc.) but is sending from a personal free-email provider.",
        ))
        raw += 30

    if features.suspicious_sender_domain:
        signals.append(_signal(
            "SUSPICIOUS_SENDER_DOMAIN", 10, "medium",
            "Suspicious sender domain",
            "The sender's domain uses security-related wording that's often abused by phishing campaigns to look official.",
        ))
        raw += 20

    if features.domain_recently_registered:
        signals.append(_signal(
            "DOMAIN_RECENTLY_REGISTERED", 30, "high",
            "Newly-registered sender domain",
            "The sender's domain was registered very recently (within the last 30 days). Phishing campaigns often use freshly-registered domains because they have no negative history yet.",
        ))
        raw += 30

    if features.is_first_time_sender:
        signals.append(_signal(
            "FIRST_TIME_SENDER", 12, "medium",
            "First-time sender",
            "You have never received an email from this address before. First-time senders are not always malicious, but for any request involving money, credentials, or urgency, treat them with extra caution.",
        ))
        raw += 20

    if features.sender_has_spam_history:
        signals.append(_signal(
            "SENDER_SPAM_HISTORY", 15, "medium",
            "Sender has spam / trash history",
            "Multiple previous emails from this sender ended up in your Spam or Trash folder. This sender has a track record of unwanted or unsafe email — increased caution is warranted.",
        ))
        raw += 25

    score = min(100, raw)

    return LayerScore(
        name="identity",
        score=score,
        confidence=1.0,
        weight=LAYER_WEIGHTS["identity"],
        signals=signals,
        evidence={"raw_sum": raw},
    )


# ============================================================
# THREAT INTEL LAYER (25%) — external (VT/AbuseIPDB) + heuristics
# ============================================================

def _score_threat_intel_layer(
    features: EmailFeatures,
    threat_intel: ThreatIntelData | None,
) -> LayerScore:
    signals: list[RiskSignal] = []

    # ---- Heuristic scoring (always runs) ----
    heuristic_raw = 0

    if features.has_executable_attachment:
        signals.append(_signal(
            "EXECUTABLE_ATTACHMENT", 35, "high",
            "Dangerous executable attachment",
            "This email has an attachment type commonly used to deliver malware. Opening it could run malicious code on your computer.",
        ))
        heuristic_raw += 50

    if features.has_macro_attachment:
        signals.append(_signal(
            "MACRO_ATTACHMENT", 30, "high",
            "Macro-enabled Office file",
            "Office files with macros can run code as soon as you enable editing. Frequently used to deliver ransomware.",
        ))
        heuristic_raw += 40

    if features.has_archive_attachment:
        signals.append(_signal(
            "ARCHIVE_ATTACHMENT", 12, "medium",
            "Archive attachment",
            "Archive files (.zip, .rar, .7z) can hide dangerous contents and bypass scanning.",
        ))
        heuristic_raw += 15

    if features.has_double_extension_attachment:
        signals.append(_signal(
            "DOUBLE_EXTENSION_ATTACHMENT", 35, "high",
            "Disguised file extension",
            "An attachment uses a double extension (e.g. Invoice.pdf.exe) to hide its real type. This is a classic malware-disguise trick.",
        ))
        heuristic_raw += 35

    if features.has_mime_extension_mismatch:
        signals.append(_signal(
            "MIME_EXTENSION_MISMATCH", 35, "high",
            "File type mismatch",
            "An attachment's declared type does not match its filename extension — the file is pretending to be something it isn't.",
        ))
        heuristic_raw += 35

    if features.recently_seen_attachment:
        signals.append(_signal(
            "RECENTLY_SEEN_ATTACHMENT", 20, "medium",
            "Brand-new attachment",
            "An attachment was first seen by VirusTotal within the last 72 hours. Brand-new files are statistically much more likely to be unknown malware.",
        ))
        heuristic_raw += 20

    if features.has_login_or_verification_url:
        signals.append(_signal(
            "LOGIN_URL", 10, "medium",
            "Login or verification link",
            "There's a link in this email pointing to a login or verification page — a classic phishing setup.",
        ))
        heuristic_raw += 20

    if features.has_link_text_href_mismatch:
        signals.append(_signal(
            "LINK_TEXT_HREF_MISMATCH", 15, "high",
            "Link text doesn't match its destination",
            "A link in this email shows one domain in its visible text but actually points somewhere else. "
            "This is the signature pattern of phishing — the anchor pretends to be a trusted brand while sending you to an attacker-controlled site.",
        ))
        heuristic_raw += 30

    if features.has_url_shortener:
        signals.append(_signal(
            "URL_SHORTENER", 10, "medium",
            "Shortened URL hides destination",
            "This email uses a URL shortener (like bit.ly), which hides where the link actually leads.",
        ))
        heuristic_raw += 20

    if features.has_suspicious_url_keywords:
        signals.append(_signal(
            "SUSPICIOUS_URL_KEYWORDS", 10, "medium",
            "Phishing-style wording in URL",
            "A URL in this email contains wording commonly used in phishing pages (account, billing, unlock, etc.).",
        ))
        heuristic_raw += 15

    heuristic_score = min(100, heuristic_raw)

    # ---- External scoring (VT + AbuseIPDB, if data available) ----
    external_score = 0
    confidence = 1.0
    evidence_external: dict = {}

    if threat_intel is not None:
        # Worst URL VT
        max_url_engines = max(
            (r.malicious_count for r in threat_intel.url_results), default=0
        )
        url_external = min(100, max_url_engines * VT_URL_FILE_ENGINE_MULTIPLIER)
        if max_url_engines > 0:
            signals.append(_signal(
                "VT_URL_FLAGGED",
                min(35, max_url_engines * 5),
                "high" if max_url_engines >= 5 else "medium",
                f"VirusTotal flagged a URL ({max_url_engines} engines)",
                f"At least one URL in this email is flagged as malicious by {max_url_engines} antivirus engines on VirusTotal.",
            ))

        # Worst attachment-hash VT
        max_file_engines = max(
            (r.malicious_count for r in threat_intel.file_results), default=0
        )
        file_external = min(100, max_file_engines * VT_URL_FILE_ENGINE_MULTIPLIER)
        if max_file_engines > 0:
            signals.append(_signal(
                "VT_FILE_FLAGGED",
                min(40, max_file_engines * 6),
                "high" if max_file_engines >= 5 else "medium",
                f"VirusTotal flagged an attachment ({max_file_engines} engines)",
                f"At least one attachment is flagged as malicious by {max_file_engines} antivirus engines on VirusTotal.",
            ))

        # AbuseIPDB
        abuseipdb_score = 0
        if threat_intel.abuseipdb_result:
            abuseipdb_score = threat_intel.abuseipdb_result.abuse_confidence
            if abuseipdb_score >= 50:
                signals.append(_signal(
                    "ABUSEIPDB_FLAGGED",
                    min(30, abuseipdb_score // 4),
                    "high" if abuseipdb_score >= 75 else "medium",
                    f"Sender IP has abuse history ({abuseipdb_score}% confidence)",
                    f"The sending IP has been reported for abuse with {abuseipdb_score}% confidence on AbuseIPDB.",
                ))

        # Worst sender-domain VT
        max_domain_engines = max(
            (r.malicious_count for r in threat_intel.domain_results), default=0
        )
        domain_external = min(100, max_domain_engines * VT_DOMAIN_IP_ENGINE_MULTIPLIER)
        if max_domain_engines > 0:
            signals.append(_signal(
                "VT_DOMAIN_FLAGGED",
                min(20, max_domain_engines * 4),
                "medium",
                f"VirusTotal flagged sender domain ({max_domain_engines} engines)",
                f"The sender's domain is flagged on VirusTotal by {max_domain_engines} engines.",
            ))

        # Worst sender-IP VT
        max_ip_engines = max(
            (r.malicious_count for r in threat_intel.ip_results), default=0
        )
        ip_external = min(100, max_ip_engines * VT_DOMAIN_IP_ENGINE_MULTIPLIER)
        if max_ip_engines > 0:
            signals.append(_signal(
                "VT_IP_FLAGGED",
                min(20, max_ip_engines * 4),
                "medium",
                f"VirusTotal flagged sender IP ({max_ip_engines} engines)",
                f"The sender's IP address is flagged on VirusTotal by {max_ip_engines} engines.",
            ))

        # Google Safe Browsing — any threat hit pushes score very high.
        gsb_external = 0
        gsb_threat_count = 0
        for r in threat_intel.safe_browsing_results:
            if r.is_threat:
                gsb_threat_count += 1
                gsb_external = 90  # Single GSB hit is high-confidence by Google's curation
                signals.append(_signal(
                    "GSB_FLAGGED",
                    35,
                    "high",
                    "Google Safe Browsing flagged a URL",
                    "Google Safe Browsing — the same database Chrome uses to warn users about dangerous sites — has classified a URL in this email as a threat (categories: "
                    + ", ".join(r.threat_types) + ").",
                ))

        # URLhaus — known malware-distribution URL.
        urlhaus_external = 0
        urlhaus_count = 0
        for r in threat_intel.urlhaus_results:
            if r.in_database:
                urlhaus_count += 1
                urlhaus_external = 90
                tags_text = ", ".join(r.tags) if r.tags else "malware"
                signals.append(_signal(
                    "URLHAUS_FLAGGED",
                    30,
                    "high",
                    "URLhaus flagged a malware-distribution URL",
                    "A URL in this email is in URLhaus, abuse.ch's database of URLs hosting malware payloads. Tags: " + tags_text + ".",
                ))

        external_score = max(
            url_external, file_external, abuseipdb_score, domain_external, ip_external,
            gsb_external, urlhaus_external,
        )
        evidence_external = {
            "max_url_engines": max_url_engines,
            "max_file_engines": max_file_engines,
            "abuseipdb_confidence": abuseipdb_score,
            "max_domain_engines": max_domain_engines,
            "max_ip_engines": max_ip_engines,
            "gsb_threats": gsb_threat_count,
            "urlhaus_hits": urlhaus_count,
        }
    else:
        # No threat-intel data — confidence drops; we still have heuristics.
        confidence = 0.7

    layer_score = max(heuristic_score, external_score)

    return LayerScore(
        name="threat_intel",
        score=layer_score,
        confidence=confidence,
        weight=LAYER_WEIGHTS["threat_intel"],
        signals=signals,
        evidence={
            "heuristic_score": heuristic_score,
            "external_score": external_score,
            **evidence_external,
        },
    )


# ============================================================
# CONTENT LAYER (10%)
# ============================================================

def _score_content_layer(features: EmailFeatures) -> LayerScore:
    signals: list[RiskSignal] = []
    raw = 0

    if features.financial_request_language:
        signals.append(_signal(
            "FINANCIAL_REQUEST", 15, "high",
            "Money or payment request",
            "The email talks about payments, invoices, transfers, or banking — a top vector for fraud and BEC scams.",
        ))
        raw += 35

    if features.credential_request_language:
        signals.append(_signal(
            "CREDENTIAL_REQUEST", 15, "high",
            "Asking for credentials",
            "The email is asking for or referencing passwords, login codes, or two-factor authentication codes.",
        ))
        raw += 35

    if features.urgent_language:
        signals.append(_signal(
            "URGENT_LANGUAGE", 8, "low",
            "Pressure-based language",
            "The email uses urgency or pressure to push you into acting quickly without thinking.",
        ))
        raw += 25

    if features.generic_greeting:
        signals.append(_signal(
            "GENERIC_GREETING", 5, "low",
            "Generic greeting",
            "The email greets you generically (\"Dear customer\") rather than by name — typical of mass phishing.",
        ))
        raw += 15

    score = min(100, raw)

    return LayerScore(
        name="content",
        score=score,
        confidence=1.0,
        weight=LAYER_WEIGHTS["content"],
        signals=signals,
        evidence={"raw_sum": raw},
    )


# ============================================================
# CLAUDE LAYER (40%)
# ============================================================

def _score_claude_layer(claude_analysis: ClaudeAnalysis | None) -> LayerScore:
    if claude_analysis is None or not claude_analysis.available:
        return LayerScore(
            name="claude",
            score=0,
            confidence=0.0,  # fail-open: this layer's contribution → 0
            weight=LAYER_WEIGHTS["claude"],
            signals=[],
            evidence={"available": False},
        )

    score = max(0, min(100, int(claude_analysis.claude_score)))
    severity = "low" if score < 35 else ("medium" if score < 70 else "high")

    # Use the first main_finding as the short signal explanation when available,
    # otherwise fall back to the potential_damage line, otherwise a generic line.
    signal_explanation = (
        (claude_analysis.main_findings[0] if claude_analysis.main_findings else "")
        or claude_analysis.potential_damage
        or "Claude analyzed the email holistically across content, intent, and context."
    )

    signal = _signal(
        "CLAUDE_AI_VERDICT",
        # Nominal "point" value for the legacy summary; the actual contribution
        # to the composite comes from the layer weight, not this number.
        max(1, score // 5),
        severity,
        f"AI analysis: {score}/100 ({claude_analysis.threat_category})",
        signal_explanation,
    )

    return LayerScore(
        name="claude",
        score=score,
        confidence=1.0,
        weight=LAYER_WEIGHTS["claude"],
        signals=[signal],
        evidence={
            "claude_score": score,
            "threat_category": claude_analysis.threat_category,
            "available": True,
        },
    )


# ============================================================
# QUARANTINE DECISION (single-tier — Malicious only)
# ============================================================

def _proven_malicious_overrides(
    features: EmailFeatures,
    threat_intel: ThreatIntelData | None,
) -> list[str]:
    """
    Return a non-empty list of trigger reasons when ANY industry-grade
    proven-malicious indicator OR a high-precision combinational pattern is
    present. These bypass the composite score and force MOVE_TO_TRASH.

    Each rule below is intentionally narrow so false-positive risk stays
    low — auto-trash is irreversible from the user's perspective.
    """
    triggers: list[str] = []

    # ============ Tier 1: industry-consensus indicators (single-source) ============
    if threat_intel is not None:
        # VirusTotal — N+ engines is the canonical "proven malicious" bar.
        for r in threat_intel.url_results:
            if r.malicious_count >= settings.VT_PROVEN_MALICIOUS_ENGINES:
                triggers.append(f"VT_URL_FLAGGED:{r.malicious_count}_engines")
        for r in threat_intel.file_results:
            if r.malicious_count >= settings.VT_PROVEN_MALICIOUS_ENGINES:
                triggers.append(f"VT_FILE_FLAGGED:{r.malicious_count}_engines")
        for r in threat_intel.domain_results:
            if r.malicious_count >= settings.VT_PROVEN_MALICIOUS_ENGINES:
                triggers.append(f"VT_DOMAIN_FLAGGED:{r.malicious_count}_engines")
        # NOTE: VT IP flag intentionally NOT used as an override. Sender IPs
        # are often shared mail infrastructure (Office365 / SendGrid / Gmail
        # relays), so a multi-engine VT IP hit can stem from one bad tenant
        # on shared infra. AbuseIPDB ≥75 confidence is a better-calibrated
        # IP-level override (it uses a community-confidence scale rather
        # than binary engine votes). The VT IP signal still contributes via
        # the threat-intel layer score — it's just not strong enough alone
        # to bypass the composite and force auto-trash.

        # AbuseIPDB — high confidence is community-verified abuse history.
        if (
            threat_intel.abuseipdb_result
            and threat_intel.abuseipdb_result.abuse_confidence
            >= settings.ABUSEIPDB_PROVEN_MALICIOUS_CONFIDENCE
        ):
            triggers.append(
                f"ABUSEIPDB_FLAGGED:{threat_intel.abuseipdb_result.abuse_confidence}%"
            )

        # Google Safe Browsing — Google's curated real-time list. Single hit is
        # high-precision (this is what Chrome uses to warn users).
        for r in threat_intel.safe_browsing_results:
            if r.is_threat:
                kinds = ",".join(r.threat_types) or "threat"
                triggers.append(f"GSB_FLAGGED:{kinds}")

        # URLhaus — community-curated malware-distribution database. Single hit
        # is high-precision (entries are hand-reviewed before publication).
        for r in threat_intel.urlhaus_results:
            if r.in_database:
                triggers.append(f"URLHAUS_FLAGGED:{r.threat or 'malware'}")

    # ============ Tier 2: high-precision combinational patterns ============
    # Each combination below is essentially never seen on legitimate mail.

    # Textbook credential phishing: brand impersonation + login URL + free-provider sender.
    if (
        features.display_name_spoofing
        and features.has_login_or_verification_url
        and features.free_provider_spoofing
    ):
        triggers.append("COMBO_BRAND_SPOOF_LOGIN_FREE_PROVIDER")

    # Textbook malware delivery: DMARC fail + executable attachment + first-time sender.
    if (
        features.dmarc_fail
        and features.has_executable_attachment
        and features.is_first_time_sender
    ):
        triggers.append("COMBO_DMARC_FAIL_EXE_FIRST_TIME")

    # Double-extension attachment from a first-time sender — no legitimate use case.
    if features.has_double_extension_attachment and features.is_first_time_sender:
        triggers.append("COMBO_DOUBLE_EXTENSION_FIRST_TIME")

    # Display-name-spoofs-brand + link-text-vs-href mismatch — precise phishing fingerprint.
    if features.display_name_spoofing and features.has_link_text_href_mismatch:
        triggers.append("COMBO_BRAND_SPOOF_LINK_MISMATCH")

    # Macro-enabled attachment from a sender who failed BOTH SPF and DKIM — almost
    # never legitimate (real macro-using senders have working email authentication).
    if features.has_macro_attachment and features.spf_fail and features.dkim_fail:
        triggers.append("COMBO_MACRO_SPF_DKIM_FAIL")

    return triggers


def _decide_quarantine(
    features: EmailFeatures,
    threat_intel: ThreatIntelData | None,
    composite_score: int,
    high_risk_threshold: int,
) -> QuarantineAction:
    """
    Quarantine decision — two paths to MOVE_TO_TRASH:

      1. Proven-malicious override — any industry-consensus indicator
         (VT N+ engines, AbuseIPDB ≥ 75, GSB hit, URLhaus hit) OR a
         high-precision combinational pattern. Bypasses the composite.
         This guarantees confirmed-bad emails are quarantined even when
         the rest of the email looks innocuous and the composite is low.

      2. Composite ≥ high_risk_threshold — the standard weighted-score path.

    The effective high_risk_threshold is supplied by the caller because it can
    drop (e.g. to 60) when Claude is unavailable — graceful degradation so the
    system can still auto-trash even if the AI layer is missing.

    Suspicious emails do NOT auto-move. The user sees the warning card and the
    SOC team is alerted (handled in the frontend), but the email stays in the
    Inbox so the user retains full agency.
    """
    # Path 1: proven-malicious override — bypasses composite entirely.
    overrides = _proven_malicious_overrides(features, threat_intel)
    if overrides:
        return QuarantineAction(
            action_taken="MOVE_TO_TRASH",
            reason="Proven-malicious indicator detected — auto-moved to Trash.",
            triggered_by=overrides,
        )

    # Path 2: composite-score threshold.
    if composite_score < high_risk_threshold:
        return QuarantineAction(action_taken="NONE", reason="", triggered_by=[])

    return QuarantineAction(
        action_taken="MOVE_TO_TRASH",
        reason="This email was identified as malicious — auto-moved to Trash.",
        triggered_by=[f"composite_score>={high_risk_threshold}"],
    )


# ============================================================
# THREAT-CATEGORY FALLBACK (used when Claude is unavailable)
# ============================================================

def classify_threat_category(signals: list[RiskSignal], risk_level: str) -> str:
    codes = {s.code for s in signals}

    if not signals or risk_level == "Safe":
        return "SAFE" if not signals else "SUSPICIOUS"

    has_malware = bool(codes & {
        "EXECUTABLE_ATTACHMENT", "MACRO_ATTACHMENT",
        "DOUBLE_EXTENSION_ATTACHMENT", "MIME_EXTENSION_MISMATCH",
        "RECENTLY_SEEN_ATTACHMENT", "VT_FILE_FLAGGED",
        "URLHAUS_FLAGGED",
    })
    has_credential_phishing = bool(codes & {
        "CREDENTIAL_REQUEST", "LOGIN_URL", "VT_URL_FLAGGED",
        "GSB_FLAGGED", "LINK_TEXT_HREF_MISMATCH",
    })
    has_financial = "FINANCIAL_REQUEST" in codes
    has_impersonation = bool(codes & {
        "DISPLAY_NAME_SPOOFING", "DMARC_FAIL", "REPLY_TO_MISMATCH",
        "FREE_PROVIDER_SPOOFING", "DOMAIN_RECENTLY_REGISTERED",
        "VT_DOMAIN_FLAGGED", "VT_IP_FLAGGED", "ABUSEIPDB_FLAGGED",
        "FIRST_TIME_SENDER", "SENDER_SPAM_HISTORY",
    })
    has_social_eng = bool(codes & {"URGENT_LANGUAGE", "GENERIC_GREETING"})

    if has_malware:
        return "MALWARE_DELIVERY"
    if has_financial and has_impersonation:
        return "BEC"
    if has_credential_phishing:
        return "PHISHING"
    if has_impersonation:
        return "IMPERSONATION"
    if has_social_eng:
        return "SOCIAL_ENGINEERING"

    return "SUSPICIOUS"


CATEGORY_ACTIONS: dict[str, list[str]] = {
    "SAFE": [],
    "SUSPICIOUS": [
        "Read the findings below before clicking any link or attachment.",
        "If you weren't expecting this email, verify the sender through a separate channel.",
    ],
    "PHISHING": [
        "Do NOT click any link in this email.",
        "Do NOT enter your password, codes, or personal details on any page it leads to.",
        "If you have an account with the company being impersonated, log in by typing the address yourself — never via the email.",
        "Report this email as phishing and delete it.",
    ],
    "BEC": [
        "Do NOT act on any payment, transfer, or banking instructions in this email.",
        "Verify the request by calling the sender on a known phone number — not by replying.",
        "Loop in your finance/security team before taking any action.",
    ],
    "MALWARE_DELIVERY": [
        "Do NOT open or download the attachment.",
        "Do NOT enable macros, content, or editing if you've already opened the file.",
        "If you've already opened it, disconnect from the network and contact your IT/security team immediately.",
    ],
    "IMPERSONATION": [
        "Treat this sender as untrusted until verified.",
        "Confirm the sender's identity through a known channel before acting on anything in the email.",
        "Don't reply with personal or sensitive information.",
    ],
    "SOCIAL_ENGINEERING": [
        "Slow down — don't act on the urgency this email is creating.",
        "Verify any claim or request independently before responding.",
    ],
}


def recommend_actions(threat_category: str, risk_level: str) -> list[str]:
    if risk_level == "Safe":
        return []
    return CATEGORY_ACTIONS.get(threat_category, CATEGORY_ACTIONS["SUSPICIOUS"])


# ============================================================
# MAIN ORCHESTRATION
# ============================================================

class ScoringEngine:
    """
    Composes the five protection layers into a single weighted score
    and risk level (Safe / Suspicious / Malicious).
    """

    def __init__(
        self,
        alert_threshold: int | None = None,
        high_risk_threshold: int | None = None,
    ):
        self.alert_threshold = alert_threshold or settings.ALERT_THRESHOLD
        self.high_risk_threshold = high_risk_threshold or settings.HIGH_RISK_THRESHOLD

    def calculate(
        self,
        features: EmailFeatures,
        threat_intel: ThreatIntelData | None = None,
        claude_analysis: ClaudeAnalysis | None = None,
    ) -> RiskResult:
        # Score each layer independently
        auth_layer = _score_auth_layer(features)
        identity_layer = _score_identity_layer(features)
        threat_layer = _score_threat_intel_layer(features, threat_intel)
        content_layer = _score_content_layer(features)
        claude_layer = _score_claude_layer(claude_analysis)

        layer_scores = [auth_layer, identity_layer, threat_layer, content_layer, claude_layer]

        # Composite weighted score: each layer's contribution = score × weight × confidence
        composite = sum(
            layer.score * layer.weight * layer.confidence for layer in layer_scores
        )
        composite_score = max(0, min(100, round(composite)))

        # Graceful degradation: when the Claude layer is unavailable, the
        # composite can never exceed 60 (other four layers sum to weight 0.60).
        # Drop the Malicious threshold to 60 for this request so the system
        # can still auto-quarantine confirmed-bad emails without the AI layer.
        claude_available = (
            claude_analysis is not None and claude_analysis.available
        )
        effective_high_risk_threshold = (
            self.high_risk_threshold
            if claude_available
            else min(self.high_risk_threshold, 60)
        )

        # Risk level from composite vs configured thresholds.
        # Three levels only: Safe / Suspicious / Malicious.
        if composite_score >= effective_high_risk_threshold:
            risk_level = "Malicious"
        elif composite_score >= self.alert_threshold:
            risk_level = "Suspicious"
        else:
            risk_level = "Safe"

        # Quarantine decision — uses the same effective threshold so risk
        # level and quarantine action stay consistent. The proven-malicious
        # override inside `_decide_quarantine` can also force MOVE_TO_TRASH
        # regardless of composite when industry-consensus indicators or
        # high-precision combinational patterns are detected.
        quarantine_action = _decide_quarantine(
            features, threat_intel, composite_score, effective_high_risk_threshold,
        )

        # Consistency: if a proven-malicious override forced MOVE_TO_TRASH but
        # the weighted composite came in below the Malicious threshold, the
        # user would otherwise see a "Suspicious" card for an email that was
        # auto-trashed. Escalate the risk level AND raise the displayed score
        # so the verdict matches the action taken.
        override_fired = (
            quarantine_action.action_taken == "MOVE_TO_TRASH"
            and not any(
                t.startswith("composite_score>=")
                for t in quarantine_action.triggered_by
            )
        )
        if override_fired:
            risk_level = "Malicious"
            composite_score = max(composite_score, 90)

        # Aggregate every layer's signals into one flat list for the UI
        all_signals: list[RiskSignal] = []
        for layer in layer_scores:
            all_signals.extend(layer.signals)

        # Threat category — Claude wins when available, fallback otherwise
        if claude_analysis is not None and claude_analysis.available:
            threat_category = claude_analysis.threat_category
        else:
            threat_category = classify_threat_category(all_signals, risk_level)

        # Action list — prefer Claude's contextual recommendations
        if (
            claude_analysis is not None
            and claude_analysis.available
            and claude_analysis.what_to_do.do
        ):
            actions = list(claude_analysis.what_to_do.do)
        else:
            actions = recommend_actions(threat_category, risk_level)

        return RiskResult(
            score=composite_score,
            risk_level=risk_level,
            alert=composite_score >= self.alert_threshold,
            threshold=self.alert_threshold,
            threat_category=threat_category,
            reasons=[s.title for s in all_signals],
            signals=all_signals,
            actions=actions,
            user_explanation="",  # filled in by app/explanation/generator.py
            features=features,
            layer_scores=layer_scores,
            threat_intel=threat_intel,
            claude_analysis=claude_analysis,
            quarantine_action=quarantine_action,
        )
