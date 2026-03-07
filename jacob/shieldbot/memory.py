"""Per-user persistent memory — backed by Backboard.io native memory.

memory="Auto" on every message means Backboard automatically extracts facts,
stores them at the assistant level, and injects relevant memories into future
context. No SQLite needed.

For the evaluator's sync interface we keep a lightweight in-process cache of
approval/denial counts so _build_prompt() has something to read immediately
without a round-trip.
"""

from __future__ import annotations

import json
import re
from typing import Any

from . import backboard_client

# In-process cache: user_id -> {approval_count, denial_count, preferences}
_cache: dict[str, dict[str, Any]] = {}


def _load_counts_from_backboard(user_id: str) -> tuple[int, int]:
    """Fetch stored memories for user and sum up approval/denial counts."""
    try:
        # Ensure the per-user assistant exists so list_memories finds the right one
        backboard_client.get_or_create_user_assistant(user_id)
        result = backboard_client.list_memories(user_id)
        memories = result.get("memories") or []
        if not isinstance(memories, list):
            # Some SDK versions return an object with items
            memories = list(memories) if memories else []

        approvals = 0
        denials = 0
        for mem in memories:
            content = mem.get("content", "") if isinstance(mem, dict) else str(mem)
            # Try parsing JSON decision records written by update_user_memory()
            try:
                data = json.loads(content)
                status = data.get("status", "")
                if status == "approved":
                    approvals += 1
                elif status == "blocked":
                    denials += 1
            except (json.JSONDecodeError, AttributeError):
                # Fall back to regex scan for plain-text summaries
                approvals += len(re.findall(r"\bapproved\b", content, re.IGNORECASE))
                denials += len(re.findall(r"\bblocked\b", content, re.IGNORECASE))
        return approvals, denials
    except Exception:
        return 0, 0


def _get_cache(user_id: str) -> dict[str, Any]:
    if user_id not in _cache:
        approvals, denials = _load_counts_from_backboard(user_id)
        _cache[user_id] = {
            "preferences": {},
            "approval_count": approvals,
            "denial_count": denials,
        }
    return _cache[user_id]


def get_user_memory(user_id: str) -> dict[str, Any]:
    """Return current in-process memory snapshot for this user."""
    return dict(_get_cache(user_id))


def update_user_memory(user_id: str, decision_record: dict[str, Any]) -> None:
    """Record a decision. Updates in-process counts and pushes to Backboard memory."""
    cache = _get_cache(user_id)

    status = decision_record.get("status", "")
    if status == "approved":
        cache["approval_count"] += 1
    elif status == "blocked":
        cache["denial_count"] += 1

    # Push to Backboard — memory="Auto" means Backboard extracts and stores the facts
    try:
        # Ensure the user has an assistant, then write a message to their thread
        # so Backboard's memory layer picks up the decision context.
        thread = backboard_client.create_thread(user_id=user_id)
        backboard_client.add_message(
            thread_id=thread["thread_id"],
            content=json.dumps(decision_record, default=str),
            memory="Auto",
            send_to_llm="false",
        )
    except Exception:
        pass


def set_user_preference(user_id: str, key: str, value: Any) -> None:
    _get_cache(user_id)["preferences"][key] = value


def clear_all() -> None:
    _cache.clear()
