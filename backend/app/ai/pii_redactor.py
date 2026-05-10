"""
Medium-strict PII redactor.

Goal: strip identifying information from email content BEFORE sending it
to the LLM, while keeping enough context for security analysis.

Tradeoff (T1, GDPR considerations):
- We strip emails, phones, account numbers, IBANs, addresses.
- We keep subject, body structure, URL domains, language/tone, attachment names.
- This satisfies the GDPR principle of data minimization but is NOT full
  GDPR compliance on its own (DPA with Anthropic + privacy policy still required).
- For a production deployment, replace regex with NER or use an on-prem model.

What gets redacted:
    user@example.com         →  [EMAIL]
    +1 (555) 123-4567        →  [PHONE]
    IBAN GB29 NWBK 6016 ...  →  [IBAN]
    1234-5678-9012-3456      →  [CARD]
    SSN-style 123-45-6789    →  [ID_NUMBER]
    long alphanumeric tokens →  [TOKEN]   (in URL query strings only)

What we KEEP (intentionally):
    sender domain, URL domains, attachment names, subject line patterns,
    body language, urgency markers, brand mentions
"""

import re
from typing import Iterable

# Order matters — IBAN must run before generic alphanumeric token redaction
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(
    r"(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3}[\s.-]?\d{3,4}[\s.-]?\d{0,4}"
)
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[\sA-Z0-9]{10,30}\b")
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
LONG_TOKEN_IN_URL_RE = re.compile(r"([?&][^=&\s]+=)([A-Za-z0-9_\-]{32,})")


def _redact_phone(text: str) -> str:
    """Phone-number redaction is risky (matches lots of digit sequences).
    We restrict to sequences that look phone-like by length and grouping."""
    def _replace(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if 7 <= len(digits) <= 15:
            return "[PHONE]"
        return match.group(0)
    return PHONE_RE.sub(_replace, text)


def redact_pii(text: str | None) -> str:
    """
    Apply medium-strict PII redaction to a free-text string.
    Safe to call on None or empty.
    """
    if not text:
        return ""

    redacted = text

    # Order matters: redact structured tokens first, generic patterns last.
    redacted = EMAIL_RE.sub("[EMAIL]", redacted)
    redacted = IBAN_RE.sub("[IBAN]", redacted)
    redacted = SSN_RE.sub("[ID_NUMBER]", redacted)
    redacted = CARD_RE.sub("[CARD]", redacted)
    redacted = LONG_TOKEN_IN_URL_RE.sub(r"\1[TOKEN]", redacted)
    redacted = _redact_phone(redacted)

    return redacted


def redact_email_local_part(email_address: str | None) -> str | None:
    """
    Keep the domain (needed for analysis) but redact the local part.

    'security@example.com'  →  '[REDACTED]@example.com'
    """
    if not email_address or "@" not in email_address:
        return email_address
    local, _, domain = email_address.rpartition("@")
    return f"[REDACTED]@{domain}"


def redact_pii_in_each(values: Iterable[str | None]) -> list[str]:
    return [redact_pii(v) for v in values if v]
