from app.scoring.models import ParsedEmail, UrlInfo, AttachmentInfo
from app.scoring.feature_extractor import extract_features
from app.scoring.engine import ScoringEngine


def test_high_risk_email():
    email = ParsedEmail(
        subject="Urgent: verify your account password",
        from_email="Security Team <security@example-login.com>",
        from_domain="example-login.com",
        reply_to_email="attacker@gmail.com",
        reply_to_domain="gmail.com",
        authentication_results="spf=fail dkim=fail dmarc=fail",
        body_text="Urgent action required. Login now to verify your password.",
        urls=[UrlInfo(url="https://bit.ly/fake-login", domain="bit.ly")],
        attachments=[AttachmentInfo(filename="invoice.xlsm")]
    )

    features = extract_features(email)
    result = ScoringEngine(alert_threshold=60, high_risk_threshold=75).calculate(features)

    assert result.alert is True
    assert result.risk_level == "high"
    assert result.score >= 75
