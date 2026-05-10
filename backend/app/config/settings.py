import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    APP_ENV: str = os.getenv("APP_ENV", "development")

    # Composite-score thresholds (0-100 scale)
    ALERT_THRESHOLD: int = int(os.getenv("ALERT_THRESHOLD", "35"))
    HIGH_RISK_THRESHOLD: int = int(os.getenv("HIGH_RISK_THRESHOLD", "70"))

    # Threat intelligence keys
    VIRUSTOTAL_API_KEY: str | None = os.getenv("VIRUSTOTAL_API_KEY") or None
    ABUSEIPDB_API_KEY: str | None = os.getenv("ABUSEIPDB_API_KEY") or None
    GOOGLE_SAFE_BROWSING_API_KEY: str | None = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or None
    URLHAUS_API_KEY: str | None = os.getenv("URLHAUS_API_KEY") or None

    # AI layer
    ANTHROPIC_API_KEY: str | None = os.getenv("ANTHROPIC_API_KEY") or None
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")

    # Two-tier quarantine policy
    SPAM_QUARANTINE_SCORE: int = int(os.getenv("SPAM_QUARANTINE_SCORE", "70"))
    VT_PROVEN_MALICIOUS_ENGINES: int = int(os.getenv("VT_PROVEN_MALICIOUS_ENGINES", "5"))
    ABUSEIPDB_PROVEN_MALICIOUS_CONFIDENCE: int = int(
        os.getenv("ABUSEIPDB_PROVEN_MALICIOUS_CONFIDENCE", "75")
    )

    # SOC alert recipient
    SOC_ALERT_EMAIL: str | None = os.getenv("SOC_ALERT_EMAIL") or None


settings = Settings()
