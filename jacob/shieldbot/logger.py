"""Audit trail logger for Shieldbot decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .types import ActionRequest, Decision


_audit_log: list[dict[str, Any]] = []


def log_decision(request: ActionRequest, decision: Decision, trust_tier: str = "medium") -> dict[str, Any]:
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
    }
    _audit_log.append(entry)
    return entry


def get_audit_log() -> list[dict[str, Any]]:
    return list(_audit_log)


def clear_log() -> None:
    _audit_log.clear()
