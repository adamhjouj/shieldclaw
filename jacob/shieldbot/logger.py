"""Audit trail logger for Shieldbot decisions.

Every decision is:
  1. Appended to an in-process list (always available, zero-latency)
  2. Shipped to Backboard as a memory entry for persistent analytics
     (fire-and-forget via a background thread — never blocks evaluation)

Backboard analytics give you a persistent, queryable history of every
security decision across all runs, visible in the Backboard dashboard.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any

import httpx

from .action_types import ActionRequest, Decision
from . import config


_audit_log: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Backboard analytics helpers
# ---------------------------------------------------------------------------

def _ship_to_backboard(entry: dict[str, Any]) -> None:
    """POST the audit entry to Backboard as a memory for analytics tracking."""
    if not config.use_backboard():
        return

    # Format as a compact, human-readable memory string so it surfaces cleanly
    # in the Backboard dashboard memory list.
    memory_content = (
        f"[ShieldBot Audit] {entry['timestamp']} | "
        f"user={entry['user_id']} | action={entry['action_type']} | "
        f"status={entry['status'].upper()} | risk={entry['risk_score']} | "
        f"tier={entry['trust_tier']} | reason={entry['reason']}"
    )

    payload = {
        "content": memory_content,
        "metadata": {
            "source": "shieldbot",
            "user_id": entry["user_id"],
            "session_id": entry["session_id"],
            "action_type": entry["action_type"],
            "status": entry["status"],
            "risk_score": entry["risk_score"],
            "trust_tier": entry["trust_tier"],
            "factors": entry.get("factors", []),
            "thread_id": entry.get("thread_id"),
        },
    }

    try:
        httpx.post(
            f"{config.BACKBOARD_BASE_URL}/memories",
            json=payload,
            headers={
                "X-API-Key": config.BACKBOARD_API_KEY,
                "Content-Type": "application/json",
            },
            timeout=10,
        )
    except Exception:
        pass  # Analytics failure must never affect security decisions


def _ship_async(entry: dict[str, Any]) -> None:
    """Fire-and-forget: ship to Backboard in a daemon thread."""
    t = threading.Thread(target=_ship_to_backboard, args=(entry,), daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def log_decision(
    request: ActionRequest,
    decision: Decision,
    trust_tier: str = "medium",
    thinking: str | None = None,
) -> dict[str, Any]:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": request.user_id,
        "session_id": request.session_id,
        "action_type": request.action_type,
        "payload": request.payload,
        "status": decision.status,
        "risk_score": decision.risk_score,
        "reason": decision.reason,
        "factors": decision.factors,
        "thread_id": decision.thread_id,
        "trust_tier": trust_tier,
        "reasoning": thinking,
    }
    _audit_log.append(entry)
    _ship_async(entry)
    return entry


def get_audit_log() -> list[dict[str, Any]]:
    return list(_audit_log)


def clear_log() -> None:
    _audit_log.clear()
