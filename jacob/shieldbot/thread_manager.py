"""Backboard-style thread manager.

Threads provide per-task/session context for Shieldbot evaluations.
This is a local mock — swap the _store backend with real Backboard calls later.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


_store: dict[str, dict[str, Any]] = {}


def get_or_create_thread(session_id: str, user_id: str) -> dict[str, Any]:
    if session_id in _store:
        return _store[session_id]

    thread = {
        "thread_id": str(uuid.uuid4()),
        "session_id": session_id,
        "user_id": user_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "history": [],
    }
    _store[session_id] = thread
    return thread


def append_to_thread(session_id: str, entry: dict[str, Any]) -> None:
    thread = _store.get(session_id)
    if thread is None:
        return
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    thread["history"].append(entry)


def get_thread(session_id: str) -> dict[str, Any] | None:
    return _store.get(session_id)


def clear_all() -> None:
    _store.clear()
