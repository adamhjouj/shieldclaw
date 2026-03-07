"""Backboard-style user memory.

Stores user preferences and prior approval/denial history.
Local mock — replace the _memory_store backend with real Backboard later.
"""

from __future__ import annotations

from typing import Any


_memory_store: dict[str, dict[str, Any]] = {}

DEFAULT_PREFERENCES: dict[str, Any] = {}


def get_user_memory(user_id: str) -> dict[str, Any]:
    if user_id not in _memory_store:
        _memory_store[user_id] = {
            "preferences": dict(DEFAULT_PREFERENCES),
            "history": [],
            "denial_count": 0,
            "approval_count": 0,
        }
    return _memory_store[user_id]


def update_user_memory(user_id: str, decision_record: dict[str, Any]) -> None:
    mem = get_user_memory(user_id)
    mem["history"].append(decision_record)
    status = decision_record.get("status", "")
    if status == "blocked":
        mem["denial_count"] += 1
    elif status == "approved":
        mem["approval_count"] += 1


def set_user_preference(user_id: str, key: str, value: Any) -> None:
    mem = get_user_memory(user_id)
    mem["preferences"][key] = value


def clear_all() -> None:
    _memory_store.clear()
