from app.scoring.models import RiskResult


SIGNAL_CATEGORIES: dict[str, str] = {
    "SPF_FAIL": "auth",
    "DKIM_FAIL": "auth",
    "DMARC_FAIL": "auth",
    "REPLY_TO_MISMATCH": "identity",
    "SUSPICIOUS_SENDER_DOMAIN": "identity",
    "DISPLAY_NAME_SPOOFING": "identity",
    "FREE_PROVIDER_SPOOFING": "identity",
    "DOMAIN_RECENTLY_REGISTERED": "identity",
    "VT_DOMAIN_FLAGGED": "identity",
    "VT_IP_FLAGGED": "identity",
    "ABUSEIPDB_FLAGGED": "identity",
    "FIRST_TIME_SENDER": "identity",
    "SENDER_SPAM_HISTORY": "identity",
    "LOGIN_URL": "url",
    "URL_SHORTENER": "url",
    "SUSPICIOUS_URL_KEYWORDS": "url",
    "VT_URL_FLAGGED": "url",
    "GSB_FLAGGED": "url",
    "URLHAUS_FLAGGED": "url",
    "LINK_TEXT_HREF_MISMATCH": "url",
    "URGENT_LANGUAGE": "social",
    "FINANCIAL_REQUEST": "social",
    "CREDENTIAL_REQUEST": "social",
    "GENERIC_GREETING": "social",
    "EXECUTABLE_ATTACHMENT": "attachment",
    "MACRO_ATTACHMENT": "attachment",
    "ARCHIVE_ATTACHMENT": "attachment",
    "DOUBLE_EXTENSION_ATTACHMENT": "attachment",
    "MIME_EXTENSION_MISMATCH": "attachment",
    "RECENTLY_SEEN_ATTACHMENT": "attachment",
    "VT_FILE_FLAGGED": "attachment",
    "CLAUDE_AI_VERDICT": "ai",
}


def generate_user_explanation(result: RiskResult) -> str:
    if not result.signals:
        return (
            "I didn't find any clear signs of phishing, spoofing, or malware in this email.\n"
            "That said, no automated check is perfect — if anything still feels off about this sender or the request, "
            "trust your instincts and verify through a separate channel before acting."
        )

    findings = "Here's what I noticed:\n" + "\n".join(
        f"  • {s.title} — {s.explanation}" for s in result.signals
    )

    narrative = compose_damage_narrative(result)

    return findings + "\n\nWhat this could mean for you:\n" + narrative


def compose_damage_narrative(result: RiskResult) -> str:
    categories_present = {
        SIGNAL_CATEGORIES.get(s.code, "other") for s in result.signals
    }

    paragraphs: list[str] = []

    if "attachment" in categories_present:
        paragraphs.append(
            "This email carries an attachment of a type commonly used to deliver malware. "
            "Opening it — or enabling macros / content if it's an Office file — could run code on your computer, "
            "steal data, or give an attacker remote access."
        )

    if "url" in categories_present and "social" in categories_present:
        paragraphs.append(
            "The combination of suspicious links and pressure-based language is a textbook phishing pattern. "
            "If you click and enter credentials, the attacker likely captures them in real time and tries to log in to your real account within minutes."
        )
    elif "url" in categories_present:
        paragraphs.append(
            "One or more links in this email look risky. Clicking could take you to a fake login page, "
            "trigger a malicious download, or expose information about your device to the attacker."
        )

    if "identity" in categories_present and "auth" in categories_present:
        paragraphs.append(
            "The sender is failing email authentication checks AND showing signs of identity spoofing. "
            "There's a strong chance this email is not from who it claims to be."
        )
    elif "identity" in categories_present:
        paragraphs.append(
            "The sender's identity doesn't quite line up — the name, domain, or reply address suggests this may be an impersonation attempt."
        )
    elif "auth" in categories_present:
        paragraphs.append(
            "This email failed one or more sender-authentication checks. That alone doesn't prove malice "
            "(some legitimate senders are misconfigured), but combined with anything else suspicious it's a strong red flag."
        )

    if "social" in categories_present and "url" not in categories_present and "attachment" not in categories_present:
        paragraphs.append(
            "Even without dangerous links or files, the language in this email is engineered to make you act fast or share something sensitive. "
            "This is the core of social engineering and the foundation of Business Email Compromise (BEC) scams — which often have NO links or attachments at all."
        )

    if not paragraphs:
        paragraphs.append(
            "I couldn't pin this to a single attack pattern, but the combination of signals is enough to be careful. "
            "Verify the sender independently before clicking, downloading, or replying with anything sensitive."
        )

    return "\n\n".join(paragraphs)
