"""
Natural Language Policy Parser for ShieldClaw.

Translates plain-English agent policy descriptions into ShieldClaw
scopes and data_access categories using Claude Haiku.

Example:
    parsed = await parse_policy("read only, no sensitive data")
    # {"scopes": ["gateway:read"], "data_access": [], "confidence": "high", ...}
"""

import os
import json
import logging

import anthropic

from data_policy import SENSITIVE_PATTERNS

logger = logging.getLogger("shieldclaw.policy_parser")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = "claude-haiku-4-5-20251001"

VALID_SCOPES = [
    "gateway:read",
    "gateway:message",
    "gateway:tools",
    "gateway:canvas",
    "gateway:tools:exec",
    "gateway:admin",
]

# Derived from data_policy — stays in sync if categories are added
VALID_DATA_ACCESS = list(SENSITIVE_PATTERNS.keys())

SAFE_MINIMUM = {
    "scopes": ["gateway:read"],
    "data_access": [],
    "confidence": "low",
    "reasoning": "Defaulted to minimal permissions.",
    "warnings": [],
}

SYSTEM_PROMPT = """You are a security policy parser for ShieldClaw, an OAuth proxy for AI agents.

Your task is to read a natural language policy description and map it to the exact valid scopes and data access categories that ShieldClaw understands.

VALID SCOPES (in order of increasing risk):
- gateway:read       — Read-only status/probe access. Low risk.
- gateway:message    — Send and receive messages (chat). Medium risk.
- gateway:tools      — Invoke tool calls. Medium risk.
- gateway:canvas     — Canvas/UI display access. Low risk.
- gateway:tools:exec — Execute arbitrary shell commands. CRITICAL risk.
- gateway:admin      — Full administrative access. CRITICAL risk.

VALID DATA_ACCESS CATEGORIES:
- credentials  — Passwords, API keys, tokens, secrets
- pii          — SSNs, emails, credit cards, phone numbers
- infra        — Database URLs, connection strings, internal IPs
- financial    — Bank accounts, balances, financial identifiers
- env_config   — Cloud credentials, service API keys

SECURITY RULES:
1. When in doubt, choose fewer permissions (principle of least privilege).
2. Never grant gateway:tools:exec or gateway:admin unless the policy EXPLICITLY requests command execution, full admin, or "all access" in unambiguous terms.
3. Never grant data access categories unless the policy explicitly names that type of data. "Read-only" means no data access.
4. If the policy says "no sensitive data" or "cannot see anything sensitive", data_access must be an empty list.
5. If the policy is completely ambiguous or nonsensical, return the minimum: scopes=["gateway:read"], data_access=[].

OUTPUT FORMAT:
You MUST respond ONLY with valid JSON. No prose, no code fences, no explanation outside the JSON.
The JSON must conform exactly to this schema:

{
  "scopes": ["<valid scope>", ...],
  "data_access": ["<valid category>", ...],
  "confidence": "high" | "medium" | "low",
  "reasoning": "<one sentence explaining the interpretation>",
  "warnings": ["<optional warning strings>"]
}

Rules:
- scopes must only contain values from the VALID SCOPES list above.
- data_access must only contain values from the VALID DATA_ACCESS CATEGORIES list.
- confidence is "high" if the policy was clear, "medium" if some inference was needed, "low" if the policy was vague and defaults were applied.
- warnings is a list of zero or more strings flagging ambiguities or notable security implications (e.g., if gateway:tools:exec was granted).
- Do not include any scope or category not in the valid lists above."""


def _safe_minimum_with_warning(warning: str) -> dict:
    result = dict(SAFE_MINIMUM)
    result["warnings"] = [warning]
    return result


def _validate_parsed(raw: dict) -> dict:
    """Strip any values the LLM hallucinated that aren't in our known-good lists."""
    scopes = [s for s in raw.get("scopes", []) if s in VALID_SCOPES]
    data_access = [d for d in raw.get("data_access", []) if d in VALID_DATA_ACCESS]
    confidence = raw.get("confidence", "low")
    if confidence not in ("high", "medium", "low"):
        confidence = "low"
    reasoning = str(raw.get("reasoning", "Policy parsed with defaults applied."))[:500]
    warnings = [str(w) for w in raw.get("warnings", [])][:10]
    return {
        "scopes": scopes,
        "data_access": data_access,
        "confidence": confidence,
        "reasoning": reasoning,
        "warnings": warnings,
    }


async def parse_policy(policy_text: str) -> dict:
    """Parse a natural language policy into ShieldClaw scopes and data_access.

    Returns a dict with keys: scopes, data_access, confidence, reasoning, warnings.
    Never raises — on any failure returns safe minimum with a warning.
    """
    if not ANTHROPIC_API_KEY:
        return _safe_minimum_with_warning(
            "ANTHROPIC_API_KEY not configured; policy parsing skipped, minimal permissions applied."
        )

    # Truncate absurdly long inputs
    text = policy_text[:2000]

    user_message = (
        f'Parse this natural language policy for an AI agent and return the JSON mapping:\n\n'
        f'Policy: "{text}"\n\n'
        f'Remember: return ONLY valid JSON matching the schema. No other text.'
    )

    try:
        client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
        message = await client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=512,
            temperature=0,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        raw_text = message.content[0].text.strip()
    except Exception as e:
        logger.warning(f"Policy parsing API call failed: {e}")
        return _safe_minimum_with_warning(
            f"Policy parsing failed ({type(e).__name__}); minimal permissions applied."
        )

    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError:
        logger.warning(f"Policy parser returned non-JSON: {raw_text[:200]}")
        return _safe_minimum_with_warning(
            "Policy response could not be parsed as JSON; minimal permissions applied."
        )

    result = _validate_parsed(raw)
    logger.info(
        f"Policy parsed: confidence={result['confidence']} "
        f"scopes={result['scopes']} data_access={result['data_access']}"
    )
    return result
