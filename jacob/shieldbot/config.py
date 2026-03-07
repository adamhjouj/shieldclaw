"""Runtime configuration for Shieldbot.

- eval_mode: toggled live to switch between "think" (Sonnet + extended thinking)
  and "fast" (Haiku, no thinking). LLM calls are routed through Backboard's
  unified API so the model can be swapped without touching Anthropic credentials.

- Backboard is used for:
    1. LLM routing (unified API, model toggling)
    2. Analytics (audit events stored as Backboard memories)

Environment variables:
    ANTHROPIC_API_KEY    — direct Anthropic key (fallback if Backboard key absent)
    BACKBOARD_API_KEY    — Backboard unified API key
    SHIELDBOT_DB_PATH    — path to SQLite file (default: shieldbot.db)
"""

from __future__ import annotations

from typing import Literal

EvalMode = Literal["think", "fast"]

# ---------------------------------------------------------------------------
# Backboard unified API
# ---------------------------------------------------------------------------
BACKBOARD_BASE_URL = "https://app.backboard.io/api"
BACKBOARD_API_KEY = "espr_1P8bkDh37cEOjxcvPDAakA56LMGyTS1IshSJOfO9ba4"

# Model identifiers as routed through Backboard
# Backboard accepts provider-prefixed model IDs (same format as OpenRouter)
BACKBOARD_THINK_MODEL = "anthropic/claude-sonnet-4-6"
BACKBOARD_FAST_MODEL = "anthropic/claude-haiku-4-5-20251001"

# ---------------------------------------------------------------------------
# Runtime config store
# ---------------------------------------------------------------------------
_config: dict = {
    "eval_mode": "think",  # "think" = Sonnet + extended thinking | "fast" = Haiku
}


def get_eval_mode() -> EvalMode:
    return _config["eval_mode"]


def set_eval_mode(mode: EvalMode) -> None:
    if mode not in ("think", "fast"):
        raise ValueError(f"Invalid eval_mode: {mode!r}. Must be 'think' or 'fast'.")
    _config["eval_mode"] = mode


def get_config() -> dict:
    return dict(_config)


def get_db_path() -> str:
    return "/Users/owner/Downloads/startup_ideas/shieldclaw/shieldbot.db"


def use_backboard() -> bool:
    """Return True if a Backboard API key is configured."""
    return bool(BACKBOARD_API_KEY)
