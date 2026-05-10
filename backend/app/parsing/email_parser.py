import base64
import re
from email.utils import parseaddr
from bs4 import BeautifulSoup
import tldextract

from app.scoring.models import ParsedEmail, UrlInfo, AttachmentInfo


URL_REGEX = re.compile(r"https?://[^\s<>'\"\\)]+", re.IGNORECASE)


def extract_domain(value: str | None) -> str | None:
    if not value:
        return None

    _, email_addr = parseaddr(value)
    if "@" not in email_addr:
        return None

    domain = email_addr.split("@")[-1].lower().strip()
    extracted = tldextract.extract(domain)
    if not extracted.domain or not extracted.suffix:
        return domain
    return f"{extracted.domain}.{extracted.suffix}"


def header_value(headers: list[dict], name: str) -> str | None:
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value")
    return None


def decode_body_data(data: str | None) -> str:
    if not data:
        return ""
    try:
        decoded = base64.urlsafe_b64decode(data.encode("utf-8"))
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return ""


def walk_parts(payload: dict) -> list[dict]:
    parts = []

    def _walk(part: dict):
        parts.append(part)
        for child in part.get("parts", []) or []:
            _walk(child)

    _walk(payload)
    return parts


def extract_body_and_attachments(payload: dict) -> tuple[str, str, list[AttachmentInfo]]:
    text_parts = []
    html_parts = []
    attachments = []

    for part in walk_parts(payload):
        mime_type = part.get("mimeType", "")
        filename = part.get("filename", "")
        body = part.get("body", {}) or {}

        if filename:
            attachments.append(
                AttachmentInfo(
                    filename=filename,
                    mime_type=mime_type,
                    size=body.get("size"),
                )
            )
            continue

        data = body.get("data")
        content = decode_body_data(data)

        if mime_type == "text/plain":
            text_parts.append(content)
        elif mime_type == "text/html":
            html_parts.append(content)

    return "\n".join(text_parts), "\n".join(html_parts), attachments


def extract_urls_from_html_and_text(body_html: str | None, body_text: str | None) -> list[UrlInfo]:
    urls: list[UrlInfo] = []

    if body_html:
        soup = BeautifulSoup(body_html, "lxml")
        for a in soup.find_all("a"):
            href = a.get("href")
            if href and href.startswith(("http://", "https://")):
                visible_text = a.get_text(" ", strip=True) or None
                urls.append(UrlInfo(url=href, domain=normalize_url_domain(href), visible_text=visible_text))

    if body_text:
        for match in URL_REGEX.findall(body_text):
            urls.append(UrlInfo(url=match, domain=normalize_url_domain(match)))

    # Deduplicate by URL
    dedup = {}
    for item in urls:
        dedup[item.url] = item
    return list(dedup.values())


def normalize_url_domain(url: str) -> str | None:
    extracted = tldextract.extract(url)
    if not extracted.domain or not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}"


def parse_gmail_message(gmail_message: dict) -> ParsedEmail:
    payload = gmail_message.get("payload", {}) or {}
    headers = payload.get("headers", []) or []

    body_text, body_html, attachments = extract_body_and_attachments(payload)
    urls = extract_urls_from_html_and_text(body_html, body_text)

    from_email = header_value(headers, "From")
    reply_to_email = header_value(headers, "Reply-To")

    return ParsedEmail(
        message_id=gmail_message.get("id"),
        subject=header_value(headers, "Subject"),
        from_email=from_email,
        from_domain=extract_domain(from_email),
        reply_to_email=reply_to_email,
        reply_to_domain=extract_domain(reply_to_email),
        return_path=header_value(headers, "Return-Path"),
        authentication_results=header_value(headers, "Authentication-Results")
            or header_value(headers, "ARC-Authentication-Results"),
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        attachments=attachments,
    )
