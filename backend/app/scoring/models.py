from pydantic import BaseModel, Field
from typing import Any, Literal


RiskLevel = Literal["Safe", "Suspicious", "Malicious"]

ThreatCategory = Literal[
    "SAFE",
    "SUSPICIOUS",
    "PHISHING",
    "BEC",
    "MALWARE_DELIVERY",
    "IMPERSONATION",
    "SOCIAL_ENGINEERING",
]

# Quarantine action taken by the addon after analysis.
# NONE = score below thresholds, no quarantine
# MOVE_TO_SPAM = composite score >= SPAM_QUARANTINE_SCORE (our judgment)
# MOVE_TO_TRASH = proven malicious by external intel (VT or AbuseIPDB consensus)
QuarantineActionType = Literal["NONE", "MOVE_TO_SPAM", "MOVE_TO_TRASH"]


class AttachmentInfo(BaseModel):
    filename: str
    mime_type: str | None = None
    size: int | None = None
    # SHA-256 computed client-side in Code.gs via Utilities.computeDigest.
    # Used for VirusTotal hash lookups without sending the file bytes.
    sha256: str | None = None


class UrlInfo(BaseModel):
    url: str
    domain: str | None = None
    visible_text: str | None = None


class RecentEmailSnapshot(BaseModel):
    """
    A truncated snapshot of one prior email from the same sender.

    Used by the anomaly-detection prompt: Claude compares the current email
    against the sender's last few emails to detect suspicious shifts in
    tone, topic, or behavior — the strongest signal for catching BEC and
    impersonation attacks.

    Privacy: bodies are PII-redacted and truncated client-side or by the
    prompt builder before being sent to Claude.
    """
    subject: str | None = None
    body_snippet: str | None = None  # truncated body, PII-redacted
    received_iso_date: str | None = None
    has_attachments: bool = False
    url_count: int = 0


class SenderHistory(BaseModel):
    """
    Sender Relationship Analytics — gathered client-side via GmailApp.search()
    by the Apps Script add-on before calling the backend. Lets us reason about
    whether the recipient has any prior context with this sender.
    """
    total_threads: int = 0  # how many threads from this sender exist in the user's mailbox
    is_first_time_sender: bool = False  # True if total_threads == 0
    has_user_replied: bool = False  # has the user ever replied to this sender
    oldest_thread_iso_date: str | None = None  # ISO-8601 of oldest known thread
    # New: how many of the sender's prior emails ended up in spam/trash.
    # If a sender has a track record of spam/trash, this email is more likely
    # to be unwanted or malicious.
    spam_count: int = 0  # threads from this sender currently in Spam
    trash_count: int = 0  # threads from this sender currently in Trash
    available: bool = False  # False if Apps Script couldn't compute (cold start, error)


class ParsedEmail(BaseModel):
    message_id: str | None = None
    subject: str | None = None
    from_email: str | None = None
    from_domain: str | None = None
    reply_to_email: str | None = None
    reply_to_domain: str | None = None
    return_path: str | None = None
    authentication_results: str | None = None
    body_text: str | None = None
    body_html: str | None = None
    urls: list[UrlInfo] = Field(default_factory=list)
    attachments: list[AttachmentInfo] = Field(default_factory=list)
    sender_history: SenderHistory | None = None
    # Up to 5 most recent emails from the same sender (excluding the
    # current one). Populated by Code.gs via GmailApp.search. Used by
    # Claude for anomaly detection — sudden topic / tone / behavior shifts.
    recent_emails_from_sender: list[RecentEmailSnapshot] = Field(default_factory=list)


class EmailFeatures(BaseModel):
    spf_fail: bool = False
    dkim_fail: bool = False
    dmarc_fail: bool = False

    reply_to_mismatch: bool = False
    suspicious_sender_domain: bool = False
    display_name_spoofing: bool = False
    free_provider_spoofing: bool = False
    # Set by the orchestrator after VT domain lookup; True if domain
    # was registered within the last 30 days.
    domain_recently_registered: bool = False
    # Set by the orchestrator from sender_history (if provided by Code.gs).
    # True if the recipient has never received an email from this sender before.
    is_first_time_sender: bool = False
    # Set by the orchestrator from sender_history. True if the recipient has
    # actively replied to this sender at any point in the past.
    has_user_replied_to_sender: bool = False
    # Set by the orchestrator from sender_history. True if the sender has a
    # significant history of being routed to Spam or Trash by the recipient.
    sender_has_spam_history: bool = False

    has_urls: bool = False
    has_login_or_verification_url: bool = False
    has_url_shortener: bool = False
    has_suspicious_url_keywords: bool = False
    # Set when a link's visible anchor text claims to point to one domain but
    # the href actually points elsewhere (e.g. anchor "paypal.com", href evil.ru).
    has_link_text_href_mismatch: bool = False

    urgent_language: bool = False
    financial_request_language: bool = False
    credential_request_language: bool = False
    generic_greeting: bool = False

    has_attachments: bool = False
    has_executable_attachment: bool = False
    has_macro_attachment: bool = False
    has_archive_attachment: bool = False
    has_double_extension_attachment: bool = False
    has_mime_extension_mismatch: bool = False
    # Set by the orchestrator after VT file lookup; True if any attachment
    # was first seen on VT within the last 72 hours.
    recently_seen_attachment: bool = False


class RiskSignal(BaseModel):
    code: str
    score: int
    severity: Literal["low", "medium", "high"]
    title: str
    explanation: str


# =============================================================
# Layered scoring — each analyzer reports an independent LayerScore.
# The orchestrator combines them via the weighted formula in engine.py.
# =============================================================


class LayerScore(BaseModel):
    """One layer's contribution to the final composite score."""
    name: Literal["auth", "threat_intel", "identity", "content", "claude"]
    score: int  # 0-100, the layer's own assessment
    confidence: float = 1.0  # 0-1; drops to 0 when a layer is unavailable
    weight: float  # the weight applied to this layer in the final score
    signals: list[RiskSignal] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)  # raw data, debuggable


# =============================================================
# Threat intelligence response shapes.
# These mirror the normalized dicts returned by app/threat_intel/*.py
# so they can be embedded in RiskResult and reach the frontend with types.
# =============================================================


class VirusTotalResult(BaseModel):
    """Normalized VT verdict for a URL, file hash, domain, or IP."""
    kind: Literal["url", "file", "domain", "ip"]
    # Identifier varies per kind; we keep it generic
    target: str

    # Engine consensus
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    timeout_count: int = 0
    total_engines: int = 0

    # VT metadata
    reputation: int | None = None
    first_submission_date: int | None = None
    last_analysis_date: int | None = None
    total_votes_harmless: int | None = None
    total_votes_malicious: int | None = None

    # Kind-specific extras
    title: str | None = None
    last_final_url: str | None = None
    threat_names: list[str] = Field(default_factory=list)
    categories: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    meaningful_name: str | None = None
    type_description: str | None = None
    type_tag: str | None = None
    size: int | None = None
    sha256: str | None = None
    md5: str | None = None
    sha1: str | None = None
    names: list[str] = Field(default_factory=list)
    popular_threat_classification: dict[str, Any] = Field(default_factory=dict)
    sandbox_verdicts: dict[str, Any] = Field(default_factory=dict)
    creation_date: int | None = None
    last_dns_records: list[dict[str, Any]] = Field(default_factory=list)
    registrar: str | None = None
    country: str | None = None
    asn: int | None = None
    as_owner: str | None = None
    network: str | None = None

    is_malicious: bool = False


class AbuseIPDBResult(BaseModel):
    """Normalized AbuseIPDB verdict for a sender IP address."""
    ip: str
    abuse_confidence: int = 0  # 0-100
    country_code: str | None = None
    country_name: str | None = None
    usage_type: str | None = None
    isp: str | None = None
    domain: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    total_reports: int = 0
    distinct_reporters: int = 0
    last_reported_at: str | None = None
    is_whitelisted: bool = False
    is_tor: bool = False
    recent_report_categories: list[Any] = Field(default_factory=list)


class UrlExpansionResult(BaseModel):
    """Where a (possibly shortened) URL actually leads after redirects."""
    original_url: str
    final_url: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    redirect_count: int = 0
    expanded: bool = False
    error: str | None = None


class SafeBrowsingResult(BaseModel):
    """Google Safe Browsing v4 Lookup API verdict for one URL."""
    url: str
    is_threat: bool = False
    threat_types: list[str] = Field(default_factory=list)  # MALWARE, SOCIAL_ENGINEERING, etc.
    platform_types: list[str] = Field(default_factory=list)


class UrlhausResult(BaseModel):
    """URLhaus (abuse.ch) verdict for one URL — malware-distribution database."""
    url: str
    in_database: bool = False
    threat: str | None = None  # e.g. "malware_download"
    tags: list[str] = Field(default_factory=list)
    url_status: str | None = None  # e.g. "online", "offline"
    date_added: str | None = None
    reporter: str | None = None


class ThreatIntelData(BaseModel):
    """Aggregate of all external threat-intel findings for an email."""
    url_results: list[VirusTotalResult] = Field(default_factory=list)
    file_results: list[VirusTotalResult] = Field(default_factory=list)
    domain_results: list[VirusTotalResult] = Field(default_factory=list)
    ip_results: list[VirusTotalResult] = Field(default_factory=list)
    abuseipdb_result: AbuseIPDBResult | None = None
    url_expansions: list[UrlExpansionResult] = Field(default_factory=list)
    sender_ip: str | None = None
    # New v2 URL reputation sources
    safe_browsing_results: list[SafeBrowsingResult] = Field(default_factory=list)
    urlhaus_results: list[UrlhausResult] = Field(default_factory=list)


# =============================================================
# Claude AI analysis output.
# This is what the LLM returns after analyzing the email + threat intel.
# All fields are written by Claude per our prompt contract.
# =============================================================


class WhatToDo(BaseModel):
    do: list[str] = Field(default_factory=list)
    do_not: list[str] = Field(default_factory=list)


class ClaudeAnalysis(BaseModel):
    claude_score: int  # 0-100, Claude's own verdict (NOT the final composite)
    threat_category: ThreatCategory
    # Up to 5 short bullets, each 1-2 sentences max, listing the most
    # important findings that drive the verdict. Each bullet must reference
    # a specific fact from the input.
    main_findings: list[str] = Field(default_factory=list)
    # 1-2 sentences in plain language describing what could happen to the
    # recipient if they comply with the email's instructions or interact
    # with it. No technical jargon.
    potential_damage: str = ""
    # Up to 3 do's and 3 don'ts, each a concrete imperative.
    what_to_do: WhatToDo = Field(default_factory=lambda: WhatToDo())
    available: bool = True  # False if Claude was unavailable / failed


# =============================================================
# Quarantine decision — what action the addon should take.
# Computed by the backend, executed by Code.gs frontend.
# =============================================================


class QuarantineAction(BaseModel):
    action_taken: QuarantineActionType = "NONE"
    reason: str = ""  # human-readable reason for the action (logged + sent to SOC)
    triggered_by: list[str] = Field(default_factory=list)  # e.g. ["composite_score>=70"] or ["VT_URL_FLAGGED:14_engines"]


# =============================================================
# Final RiskResult — what the API returns to the frontend.
# All new fields are additive; legacy callers continue to work.
# =============================================================


class RiskResult(BaseModel):
    score: int
    risk_level: RiskLevel
    alert: bool
    threshold: int
    threat_category: ThreatCategory = "SAFE"
    reasons: list[str]
    signals: list[RiskSignal]
    actions: list[str] = Field(default_factory=list)
    user_explanation: str
    features: EmailFeatures

    # New additive fields
    layer_scores: list[LayerScore] = Field(default_factory=list)
    threat_intel: ThreatIntelData | None = None
    claude_analysis: ClaudeAnalysis | None = None
    quarantine_action: QuarantineAction = Field(default_factory=QuarantineAction)
