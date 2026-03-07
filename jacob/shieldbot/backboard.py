"""Backboard abstraction layer.

Clean wrapper for thread management, memory, and decision trace logging.
Currently backed by local in-memory stores. Swap the implementation functions
to point at real Backboard.io API calls when ready.

This module is the single integration point — nothing else in shieldbot
should talk to Backboard directly.
"""

from __future__ import annotations

import json
from typing import Any

from . import thread_manager, memory
from .trace import DecisionTrace
from .capture import InteractionRecord


# ── Threads ──

def get_or_create_thread(user_id: str, session_id: str, action_type: str = "") -> dict[str, Any]:
    thread = thread_manager.get_or_create_thread(session_id, user_id)
    if action_type:
        thread.setdefault("last_action_type", action_type)
    return thread


def append_thread_event(thread_id: str, session_id: str, event: dict[str, Any]) -> None:
    thread_manager.append_to_thread(session_id, event)


def get_thread_history(session_id: str) -> list[dict[str, Any]]:
    thread = thread_manager.get_thread(session_id)
    if thread is None:
        return []
    return thread.get("history", [])


# ── Memory ──

def get_user_memory(user_id: str) -> dict[str, Any]:
    return memory.get_user_memory(user_id)


def update_user_memory(user_id: str, memory_entry: dict[str, Any]) -> None:
    memory.update_user_memory(user_id, memory_entry)


def set_user_preference(user_id: str, key: str, value: Any) -> None:
    memory.set_user_preference(user_id, key, value)


# ── Decision trace logging ──

_trace_log: list[dict[str, Any]] = []


def log_decision_trace(thread_id: str, session_id: str, trace: DecisionTrace) -> None:
    trace_dict = trace.to_dict()
    _trace_log.append(trace_dict)
    thread_manager.append_to_thread(session_id, {
        "event_type": "decision_trace",
        "trace_id": trace.trace_id,
        "action_type": trace.action_type,
        "decision": trace.final_decision,
        "risk_score": trace.risk_score,
        "reason": trace.final_reason,
        "risk_factors": trace.detected_risk_factors,
        "matched_rules": trace.matched_rules,
        "matched_preferences": trace.matched_preferences,
    })


def get_trace_log() -> list[dict[str, Any]]:
    return list(_trace_log)


# ── Full interaction recording ──

def record_interaction(session_id: str, record: InteractionRecord) -> None:
    """Store a full OpenClaw interaction (input + output + decision) in the thread."""
    thread_manager.append_to_thread(session_id, {
        "event_type": "openclaw_interaction",
        **record.to_dict(),
    })


# ── Reset ──

def clear_all() -> None:
    thread_manager.clear_all()
    memory.clear_all()
    _trace_log.clear()
