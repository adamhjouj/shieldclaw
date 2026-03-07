"""User memory — real Backboard.io memory.

Decision records are stored as Backboard memories with metadata tags.
Local mirror kept for fast in-process reads.
"""

from __future__ import annotations

import json
from typing import Any

from . import backboard_client


_local_store: dict[str, dict[str, Any]] = {}

DEFAULT_PREFERENCES: dict[str, Any] = {}


def get_user_memory(user_id: str) -> dict[str, Any]:
    return _local_get(user_id)


def update_user_memory(user_id: str, decision_record: dict[str, Any]) -> None:
    _local_update(user_id, decision_record)

    backboard_client.add_memory(
        content=json.dumps(decision_record, default=str),
        metadata={"user_id": user_id, "type": "decision"},
    )


def set_user_preference(user_id: str, key: str, value: Any) -> None:
    mem = _local_get(user_id)
    mem["preferences"][key] = value

    backboard_client.add_memory(
        content=json.dumps({key: value}),
        metadata={"user_id": user_id, "type": "preference"},
    )


# ── Local mirror ──

def _local_get(user_id: str) -> dict[str, Any]:
    if user_id not in _local_store:
        _local_store[user_id] = {
            "preferences": dict(DEFAULT_PREFERENCES),
            "history": [],
            "denial_count": 0,
            "approval_count": 0,
        }
    return _local_store[user_id]


def _local_update(user_id: str, decision_record: dict[str, Any]) -> None:
    mem = _local_get(user_id)
    mem["history"].append(decision_record)
    status = decision_record.get("status", "")
    if status == "blocked":
        mem["denial_count"] += 1
    elif status == "approved":
        mem["approval_count"] += 1


def clear_all() -> None:
    _local_store.clear()
