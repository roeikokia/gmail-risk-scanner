import re
from email.utils import parseaddr
from app.scoring.models import ParsedEmail, EmailFeatures


KNOWN_BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com", "azure.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "whatsapp": {"whatsapp.com"},
    "spotify": {"spotify.com"},
}

FREE_EMAIL_PROVIDERS: set[str] = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "gmx.com",
    "zoho.com",
}

BUSINESS_ROLE_KEYWORDS: list[str] = [
    "support", "security", "admin", "helpdesk", "help desk", "service desk",
    "it team", "it department", "billing", "accounting", "finance", "hr",
    "human resources", "payroll", "no-reply", "noreply", "notifications",
    "alerts", "team", "official", "verification", "compliance",
    "תמיכה", "אבטחה", "שירות", "כספים", "חשבונאות",
]


SUSPICIOUS_TLDS = {
    ".zip", ".mov",                 # Google's 2023 TLD launch — heavily abused for phishing
    ".xyz", ".top", ".click",       # cheap, disproportionately phishing-heavy
    ".tk", ".cf", ".ml", ".ga",     # Freenom free TLDs — historically the worst phishing TLDs
    ".rest", ".country", ".kim",    # cheap registries with high spam ratio
    ".work", ".support", ".bid",    # ditto
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "lnkd.in"
}

LOGIN_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "reset",
    "password", "account", "secure", "auth", "mfa"
]

SUSPICIOUS_URL_KEYWORDS = [
    "update-payment", "wallet", "invoice", "security-alert", "unlock",
    "confirm", "suspend", "billing", "credential"
]

URGENT_WORDS = [
    "urgent", "immediately", "action required", "last warning",
    "חשוב", "דחוף", "מיידי", "פעולה נדרשת", "התראה אחרונה"
]

FINANCIAL_WORDS = [
    "wire transfer", "bank account", "iban", "payment", "invoice",
    "refund", "billing", "העברה בנקאית", "תשלום", "חשבונית", "פרטי בנק"
]

CREDENTIAL_WORDS = [
    "password", "otp", "verification code", "2fa", "mfa", "login",
    "סיסמה", "קוד אימות", "התחברות", "אימות חשבון"
]

GENERIC_GREETINGS = [
    "dear user", "dear customer", "hello customer", "שלום לקוח", "משתמש יקר"
]

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".jse", ".vbs", ".ps1", ".msi"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".xltm", ".dotm"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".gz", ".tar"
}


def contains_any(text: str, keywords: list[str]) -> bool:
    text_l = text.lower()
    return any(k.lower() in text_l for k in keywords)


def auth_failed(auth_header: str | None, mechanism: str) -> bool:
    if not auth_header:
        return False

    pattern = rf"{mechanism}\s*=\s*fail"
    return re.search(pattern, auth_header, flags=re.IGNORECASE) is not None


def file_has_extension(filename: str, extensions: set[str]) -> bool:
    filename_l = filename.lower()
    return any(filename_l.endswith(ext) for ext in extensions)


# All "dangerous" extensions across the three categories. Used to detect
# double-extension disguises like Invoice.pdf.exe / Report.docx.scr.
_ALL_DANGEROUS_EXTENSIONS = (
    EXECUTABLE_EXTENSIONS | MACRO_EXTENSIONS | ARCHIVE_EXTENSIONS
)

# "Innocuous-looking" extensions an attacker tends to put first to disguise
# the real (dangerous) extension. e.g. invoice.PDF.exe, photo.JPG.scr
_INNOCUOUS_DECOY_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".txt", ".html", ".htm",
    ".csv", ".rtf", ".odt",
}


def has_double_extension(filename: str) -> bool:
    """
    Detect double-extension disguises like 'Invoice.pdf.exe'.
    Pattern: <name>.<innocuous>.<dangerous>
    """
    if not filename:
        return False
    name_l = filename.lower()

    # Need at least two dots (so two extensions exist)
    if name_l.count(".") < 2:
        return False

    parts = name_l.rsplit(".", 2)  # ['invoice', 'pdf', 'exe']
    if len(parts) < 3:
        return False

    inner_ext = "." + parts[-2]
    final_ext = "." + parts[-1]

    return (
        inner_ext in _INNOCUOUS_DECOY_EXTENSIONS
        and final_ext in _ALL_DANGEROUS_EXTENSIONS
    )


# Map of "expected" file extensions for common MIME types.
# When the declared MIME type is in this map but the filename extension
# is not in the corresponding set, that's a mismatch.
_MIME_TO_EXPECTED_EXTENSIONS: dict[str, set[str]] = {
    "application/pdf": {".pdf"},
    "image/png": {".png"},
    "image/jpeg": {".jpg", ".jpeg"},
    "image/gif": {".gif"},
    "image/webp": {".webp"},
    "image/svg+xml": {".svg"},
    "text/plain": {".txt"},
    "text/html": {".html", ".htm"},
    "text/csv": {".csv"},
    "application/json": {".json"},
    "application/xml": {".xml"},
    "application/msword": {".doc"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {".docx"},
    "application/vnd.ms-excel": {".xls"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {".xlsx"},
    "application/vnd.ms-powerpoint": {".ppt"},
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {".pptx"},
    "application/zip": {".zip"},
    "application/x-rar-compressed": {".rar"},
    "application/x-7z-compressed": {".7z"},
}


def has_mime_extension_mismatch(filename: str, mime_type: str | None) -> bool:
    """
    Detect when the declared MIME type doesn't match the filename extension.
    e.g. file claims to be image/png but is named 'invoice.exe'.

    Only fires when:
      - We have a confident expected-extension mapping for the MIME type
      - The filename has an extension
      - That extension is NOT in the expected set for the MIME type
    """
    if not filename or not mime_type:
        return False

    expected = _MIME_TO_EXPECTED_EXTENSIONS.get(mime_type.lower().strip())
    if not expected:
        return False  # we don't have a strong opinion on this MIME type

    name_l = filename.lower()
    if "." not in name_l:
        return True  # MIME says PDF but no extension at all → mismatch

    final_ext = "." + name_l.rsplit(".", 1)[-1]
    return final_ext not in expected


def extract_display_name(from_email: str | None) -> str:
    if not from_email:
        return ""
    display_name, _ = parseaddr(from_email)
    return (display_name or "").strip().lower()


def is_display_name_spoofing_brand(display_name: str, from_domain: str | None) -> bool:
    if not display_name or not from_domain:
        return False

    from_domain_l = from_domain.lower()

    for brand, legitimate_domains in KNOWN_BRANDS.items():
        if brand in display_name:
            if not any(
                from_domain_l == d or from_domain_l.endswith("." + d)
                for d in legitimate_domains
            ):
                return True
    return False


def display_name_contains_foreign_email(display_name: str, from_domain: str | None) -> bool:
    """
    Detect 'From: "ceo@company.com" <attacker@gmail.com>' — a classic
    impersonation trick where the display name itself is an email address
    designed to look like the real sender, while the actual envelope sender
    is different. Flag when a display-name email's domain doesn't match
    the actual From domain.
    """
    if not display_name or not from_domain:
        return False
    match = re.search(r"[\w.+\-]+@([\w\-]+\.[\w.\-]+)", display_name)
    if not match:
        return False
    spoofed_domain = match.group(1).lower().rstrip(".")
    return spoofed_domain != from_domain.lower()


_DOMAIN_IN_TEXT_RE = re.compile(r"(?:https?://)?([a-z0-9][a-z0-9\-]*\.[a-z0-9\-.]+)", re.IGNORECASE)


def link_text_href_mismatch(visible_text: str | None, href_domain: str | None) -> bool:
    """
    Detect classic phishing: anchor visible text says one domain, href points
    elsewhere. e.g. <a href="evil.ru">paypal.com</a>.

    Only fires when the visible text contains a recognizable domain AND that
    domain doesn't match the href's actual domain. Plain anchors with no
    domain in their text ("Click here") return False.
    """
    if not visible_text or not href_domain:
        return False
    href_domain_l = href_domain.lower().lstrip(".")
    for match in _DOMAIN_IN_TEXT_RE.finditer(visible_text):
        claimed = match.group(1).lower().rstrip(".")
        # Need at least one dot AND a TLD-ish suffix to count as a domain claim.
        if "." not in claimed or len(claimed) < 4:
            continue
        # Exact match or proper subdomain match → fine.
        if claimed == href_domain_l or href_domain_l.endswith("." + claimed) or claimed.endswith("." + href_domain_l):
            continue
        return True
    return False


def is_free_provider_role_spoofing(display_name: str, from_domain: str | None) -> bool:
    if not display_name or not from_domain:
        return False

    if from_domain.lower() not in FREE_EMAIL_PROVIDERS:
        return False

    return any(role in display_name for role in BUSINESS_ROLE_KEYWORDS)


def extract_features(email: ParsedEmail) -> EmailFeatures:
    combined_text = " ".join([
        email.subject or "",
        email.body_text or "",
        Beautiful_html_to_text_fallback(email.body_html or ""),
    ])

    url_text = " ".join([u.url for u in email.urls])

    display_name = extract_display_name(email.from_email)

    return EmailFeatures(
        spf_fail=auth_failed(email.authentication_results, "spf"),
        dkim_fail=auth_failed(email.authentication_results, "dkim"),
        dmarc_fail=auth_failed(email.authentication_results, "dmarc"),

        reply_to_mismatch=bool(
            email.reply_to_domain
            and email.from_domain
            and email.reply_to_domain != email.from_domain
        ),

        suspicious_sender_domain=bool(
            email.from_domain
            and (
                (
                    any(x in email.from_domain for x in ["security", "verify", "login", "support"])
                    and not email.from_domain.endswith(("google.com", "microsoft.com", "apple.com"))
                )
                # Punycode (IDN) sender domain — `xn--` is the ASCII prefix for
                # internationalized domains and is the standard mechanism behind
                # homograph attacks (e.g. `xn--pypal-7vc.com` rendering as
                # "pаypal.com" with a Cyrillic 'а'). Flag any punycode sender
                # domain; Claude can disambiguate legitimate non-English brands.
                or "xn--" in email.from_domain.lower()
                # High-abuse TLDs — disproportionately used for phishing.
                or any(email.from_domain.lower().endswith(tld) for tld in SUSPICIOUS_TLDS)
            )
        ),

        display_name_spoofing=(
            is_display_name_spoofing_brand(display_name, email.from_domain)
            or display_name_contains_foreign_email(display_name, email.from_domain)
        ),
        free_provider_spoofing=is_free_provider_role_spoofing(display_name, email.from_domain),

        has_urls=len(email.urls) > 0,
        has_login_or_verification_url=contains_any(url_text, LOGIN_KEYWORDS),
        has_url_shortener=any((u.domain or "") in SHORTENER_DOMAINS for u in email.urls),
        has_suspicious_url_keywords=contains_any(url_text, SUSPICIOUS_URL_KEYWORDS),
        has_link_text_href_mismatch=any(
            link_text_href_mismatch(u.visible_text, u.domain) for u in email.urls
        ),

        urgent_language=contains_any(combined_text, URGENT_WORDS),
        financial_request_language=contains_any(combined_text, FINANCIAL_WORDS),
        credential_request_language=contains_any(combined_text, CREDENTIAL_WORDS),
        generic_greeting=contains_any(combined_text, GENERIC_GREETINGS),

        has_attachments=len(email.attachments) > 0,
        has_executable_attachment=any(file_has_extension(a.filename, EXECUTABLE_EXTENSIONS) for a in email.attachments),
        has_macro_attachment=any(file_has_extension(a.filename, MACRO_EXTENSIONS) for a in email.attachments),
        has_archive_attachment=any(file_has_extension(a.filename, ARCHIVE_EXTENSIONS) for a in email.attachments),
        has_double_extension_attachment=any(has_double_extension(a.filename) for a in email.attachments),
        has_mime_extension_mismatch=any(
            has_mime_extension_mismatch(a.filename, a.mime_type) for a in email.attachments
        ),
    )


def Beautiful_html_to_text_fallback(html: str) -> str:
    # Lightweight fallback to avoid making feature extraction dependent on exact HTML structure.
    return re.sub(r"<[^>]+>", " ", html)
