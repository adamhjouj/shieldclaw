"""
Data Isolation Policy for ShieldClaw.

Controls what DATA an agent identity can see in responses,
separate from what ROUTES it can access (that's scope enforcement).

The human owns all their data. The agent only sees what the policy allows.
This is the core value prop: your AI assistant doesn't need your SSN to write code.

Policies are set per-agent at registration time and enforced on every proxied response.
"""

import re
import json
import logging
from typing import Optional

logger = logging.getLogger("shieldclaw.data_policy")

# --- Sensitive Data Patterns ---
# These patterns match common secrets/PII in response bodies.
# When an agent lacks the corresponding data_access grant, matches get redacted.

SENSITIVE_PATTERNS = {
    # Secrets & credentials
    "credentials": {
        "patterns": [
            r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+',
            r'(?i)(secret|client_secret)\s*[=:]\s*\S+',
            r'(?i)(api_key|apikey|api-key)\s*[=:]\s*\S+',
            r'(?i)(access_token|auth_token|bearer)\s*[=:]\s*\S+',
            r'(?i)(private_key|private-key)[\s=:]+\S+',
            r'(?i)"(password|secret|api_key|token|private_key)"\s*:\s*"[^"]*"',
        ],
        "description": "Passwords, API keys, tokens, secrets",
    },
    # Personal identifiable information
    "pii": {
        "patterns": [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # credit card
            r'(?i)(phone|tel|mobile)\s*[=:]\s*[\d\s\-\+\(\)]+',
            r'(?i)(ssn|social.security)\s*[=:]\s*\S+',
            r'(?i)(date.of.birth|dob|birthday)\s*[=:]\s*\S+',
        ],
        "description": "SSNs, emails, credit cards, phone numbers, DOB",
    },
    # Infrastructure / network info
    "infra": {
        "patterns": [
            r'(?i)(database_url|db_url|connection_string)\s*[=:]\s*\S+',
            r'(?i)(redis_url|mongo_uri|postgres)\s*[=:]\s*\S+',
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b',  # IP addresses
            r'(?i)(hostname|internal_host)\s*[=:]\s*\S+',
        ],
        "description": "Database URLs, connection strings, internal IPs",
    },
    # Financial data
    "financial": {
        "patterns": [
            r'(?i)(account.number|acct.no|routing.number)\s*[=:]\s*\S+',
            r'(?i)(balance|salary|income|revenue)\s*[=:]\s*[\$\d,\.]+',
            r'(?i)(bank|iban|swift|bic)\s*[=:]\s*\S+',
        ],
        "description": "Bank accounts, balances, financial identifiers",
    },
    # Environment / config
    "env_config": {
        "patterns": [
            r'(?i)(AWS_ACCESS_KEY|AWS_SECRET)\s*[=:]\s*\S+',
            r'(?i)(GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN)\s*[=:]\s*\S+',
            r'(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY)\s*[=:]\s*\S+',
            r'(?i)(STRIPE_KEY|TWILIO_SID)\s*[=:]\s*\S+',
        ],
        "description": "Cloud credentials, service API keys, env vars",
    },
}

# Compiled patterns cache
_compiled: dict[str, list[re.Pattern]] = {}


def _get_compiled(category: str) -> list[re.Pattern]:
    if category not in _compiled:
        _compiled[category] = [
            re.compile(p) for p in SENSITIVE_PATTERNS[category]["patterns"]
        ]
    return _compiled[category]


# --- Data Access Levels ---
# When registering an agent, the owner specifies which data categories the agent can see.
# Anything not granted gets redacted from responses.

# Default: agents can't see any sensitive data categories
DEFAULT_AGENT_DATA_ACCESS: set[str] = set()

# Humans see everything (it's their data)
HUMAN_DATA_ACCESS: set[str] = {"credentials", "pii", "infra", "financial", "env_config"}


def redact_response(content: bytes, identity: dict, agent_data_access: Optional[set[str]] = None) -> bytes:
    """Redact sensitive data from a response body based on identity type and data access policy.

    - Humans: no redaction (it's their data)
    - Agents: redact any category not in their data_access grant
    """
    if not identity.get("is_agent"):
        return content

    # What this agent is allowed to see
    allowed = agent_data_access or DEFAULT_AGENT_DATA_ACCESS

    # If agent has full data access, skip redaction
    if allowed >= HUMAN_DATA_ACCESS:
        return content

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content

    redacted_categories = []

    for category, info in SENSITIVE_PATTERNS.items():
        if category in allowed:
            continue  # agent is allowed to see this category

        patterns = _get_compiled(category)
        for pattern in patterns:
            new_text = pattern.sub(f"[REDACTED:{category}]", text)
            if new_text != text:
                text = new_text
                if category not in redacted_categories:
                    redacted_categories.append(category)

    if redacted_categories:
        agent_name = identity.get("agent_name", "unknown")
        logger.info(
            f"Redacted {redacted_categories} from response for agent={agent_name}"
        )

    return text.encode("utf-8")


def redact_json_fields(data: dict, identity: dict, agent_data_access: Optional[set[str]] = None) -> dict:
    """Walk a JSON response and redact sensitive field values based on data policy.

    More precise than regex — looks at JSON keys and redacts values of known-sensitive fields.
    """
    if not identity.get("is_agent"):
        return data

    allowed = agent_data_access or DEFAULT_AGENT_DATA_ACCESS

    SENSITIVE_KEYS_BY_CATEGORY = {
        "credentials": {
            "password", "passwd", "secret", "client_secret", "api_key",
            "apikey", "access_token", "auth_token", "token", "private_key",
            "refresh_token",
        },
        "pii": {
            "email", "phone", "ssn", "social_security", "date_of_birth",
            "dob", "address", "home_address",
        },
        "infra": {
            "database_url", "db_url", "connection_string", "redis_url",
            "mongo_uri", "internal_host", "hostname",
        },
        "financial": {
            "account_number", "routing_number", "balance", "salary",
            "income", "iban", "swift", "bank_account",
        },
        "env_config": {
            "aws_access_key", "aws_secret", "github_token", "openai_api_key",
            "anthropic_api_key", "stripe_key",
        },
    }

    def _walk(obj):
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                key_lower = key.lower().replace("-", "_")
                redacted = False
                for category, keys in SENSITIVE_KEYS_BY_CATEGORY.items():
                    if category not in allowed and key_lower in keys:
                        result[key] = f"[REDACTED:{category}]"
                        redacted = True
                        break
                if not redacted:
                    result[key] = _walk(value)
            return result
        elif isinstance(obj, list):
            return [_walk(item) for item in obj]
        return obj

    return _walk(data)


def get_data_policy_summary(agent_data_access: Optional[set[str]] = None) -> dict:
    """Return a summary of what data categories are visible vs redacted."""
    allowed = agent_data_access or DEFAULT_AGENT_DATA_ACCESS

    visible = {}
    redacted = {}
    for category, info in SENSITIVE_PATTERNS.items():
        entry = {"description": info["description"]}
        if category in allowed:
            visible[category] = entry
        else:
            redacted[category] = entry

    return {
        "visible_categories": visible,
        "redacted_categories": redacted,
    }
