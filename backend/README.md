# Gmail Risk Scanner Backend

## What this backend does

This Python FastAPI backend receives a parsed email object, extracts suspicious security features, calculates a maliciousness score, and returns a user-facing explanation.

## Run locally

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Analyze endpoint

```text
POST /api/analyze-email
```

Body:

```json
{
  "email": {
    "subject": "Urgent: verify your password",
    "from_email": "Security <security@example-login.com>",
    "from_domain": "example-login.com",
    "reply_to_email": "attacker@gmail.com",
    "reply_to_domain": "gmail.com",
    "authentication_results": "spf=fail dkim=fail dmarc=fail",
    "body_text": "Urgent login required",
    "urls": [
      {
        "url": "https://bit.ly/fake-login",
        "domain": "bit.ly"
      }
    ],
    "attachments": [
      {
        "filename": "invoice.xlsm"
      }
    ]
  }
}
```

## Important architecture decision

This version is stateless:
- It does not store email bodies.
- It does not require a database.
- It is database-ready for future sender history, feedback, whitelist/blacklist, and behavioral analysis.
