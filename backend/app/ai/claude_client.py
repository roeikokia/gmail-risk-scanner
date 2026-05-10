"""
Anthropic Claude client.

Sends the system + user prompt assembled by prompt_builder.py and parses
the JSON response into a ClaudeAnalysis model.

Design decisions:
- Fail-open: if the key is missing, the API errors out, or the response
  cannot be parsed, we return ClaudeAnalysis(available=False, ...) so the
  rest of the pipeline still produces a usable score from the deterministic
  layers. The frontend surfaces "AI analysis unavailable" to the user.
- We strip markdown code fences from Claude's output before parsing
  because Claude occasionally wraps JSON in ```json ... ``` despite our
  instructions.
- Token budget: max_tokens=1024 is generous for our schema (~700 tokens
  output typical) without overspending if Claude rambles.
"""

import json
import logging
import re
from typing import Any

from app.ai.prompt_builder import SYSTEM_PROMPT, build_user_prompt
from app.config.settings import settings
from app.scoring.models import (
    ClaudeAnalysis,
    EmailFeatures,
    ParsedEmail,
    ThreatIntelData,
    WhatToDo,
)

logger = logging.getLogger(__name__)


# Tunable: how many tokens Claude can produce per call.
MAX_OUTPUT_TOKENS = 1024


# Strip ```json ... ``` or ``` ... ``` wrappers if Claude includes them.
_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _is_configured() -> bool:
    return bool(settings.ANTHROPIC_API_KEY)


def _build_unavailable_result(reason: str) -> ClaudeAnalysis:
    """Constructs a fail-open ClaudeAnalysis when Claude can't be used."""
    logger.warning("Claude unavailable: %s", reason)
    return ClaudeAnalysis(
        claude_score=0,
        threat_category="SAFE",
        main_findings=[],
        potential_damage="",
        what_to_do=WhatToDo(do=[], do_not=[]),
        available=False,
    )


def _strip_code_fences(raw: str) -> str:
    """Remove markdown code fences Claude may wrap JSON in."""
    return _CODE_FENCE_RE.sub("", raw.strip()).strip()


def _coerce_score(value: Any) -> int:
    """Best-effort coercion of Claude's score field to an int 0-100."""
    try:
        score = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, score))


def _coerce_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if v]


def _parse_claude_json(raw_text: str) -> ClaudeAnalysis | None:
    """
    Parse Claude's text response into a ClaudeAnalysis.
    Returns None if the response is not valid JSON or doesn't fit our schema.
    """
    cleaned = _strip_code_fences(raw_text)

    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.warning("Claude JSON parse failed: %s | raw: %s", exc, cleaned[:300])
        return None

    if not isinstance(payload, dict):
        logger.warning("Claude response is not a JSON object: %r", type(payload))
        return None

    what_to_do_raw = payload.get("what_to_do") or {}
    if not isinstance(what_to_do_raw, dict):
        what_to_do_raw = {}

    threat_category = payload.get("threat_category", "SUSPICIOUS")
    valid_categories = {
        "SAFE", "SUSPICIOUS", "PHISHING", "BEC",
        "MALWARE_DELIVERY", "IMPERSONATION", "SOCIAL_ENGINEERING",
    }
    if threat_category not in valid_categories:
        logger.warning("Claude returned invalid threat_category: %r", threat_category)
        threat_category = "SUSPICIOUS"

    # Enforce the schema caps so a misbehaving model doesn't break the UI:
    main_findings = _coerce_str_list(payload.get("main_findings"))[:5]

    do_items = _coerce_str_list(what_to_do_raw.get("do"))[:3]
    do_not_items = _coerce_str_list(what_to_do_raw.get("do_not"))[:3]

    return ClaudeAnalysis(
        claude_score=_coerce_score(payload.get("claude_score")),
        threat_category=threat_category,
        main_findings=main_findings,
        potential_damage=str(payload.get("potential_damage") or ""),
        what_to_do=WhatToDo(do=do_items, do_not=do_not_items),
        available=True,
    )


def analyze_with_claude(
    email: ParsedEmail,
    features: EmailFeatures,
    threat_intel: ThreatIntelData | None,
) -> ClaudeAnalysis:
    """
    Send the email + features + threat intel to Claude and return the
    structured analysis.

    Always returns a ClaudeAnalysis. On any failure, returns a fail-open
    instance with available=False.
    """
    if not _is_configured():
        return _build_unavailable_result("API key not configured")

    # Lazy import so the rest of the system works even if anthropic isn't installed
    try:
        import anthropic
    except ImportError:
        return _build_unavailable_result("anthropic SDK not installed")

    user_prompt = build_user_prompt(email, features, threat_intel)

    try:
        client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        response = client.messages.create(
            model=settings.ANTHROPIC_MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
    except anthropic.APIStatusError as exc:
        return _build_unavailable_result(f"API status error {exc.status_code}")
    except anthropic.APIConnectionError:
        return _build_unavailable_result("connection error")
    except anthropic.RateLimitError:
        return _build_unavailable_result("rate limited")
    except Exception as exc:
        logger.exception("Unexpected Claude API error")
        return _build_unavailable_result(f"unexpected error: {exc.__class__.__name__}")

    # Extract text from the response. Claude returns a list of content blocks;
    # we want the first text block.
    raw_text: str = ""
    for block in response.content or []:
        if getattr(block, "type", None) == "text":
            raw_text = getattr(block, "text", "") or ""
            break

    if not raw_text:
        return _build_unavailable_result("empty response from Claude")

    parsed = _parse_claude_json(raw_text)
    if parsed is None:
        return _build_unavailable_result("response did not match expected schema")

    return parsed
