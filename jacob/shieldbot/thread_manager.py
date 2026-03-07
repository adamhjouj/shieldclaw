"""Thread manager — Backboard.io threads, no SQLite.

Every session gets a real Backboard thread tied to the user's assistant.
Thread history is kept in-process for the current session; Backboard's
memory layer persists the important facts across restarts automatically.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from . import backboard_client

# In-process store: session_id -> thread dict
_threads: dict[str, dict[str, Any]] = {}


def get_or_create_thread(session_id: str, user_id: str) -> dict[str, Any]:
    if session_id in _threads:
        return _threads[session_id]

    try:
        bb_thread = backboard_client.create_thread(user_id=user_id)
        thread_id = bb_thread["thread_id"]
    except Exception:
        thread_id = str(uuid.uuid4())

    thread = {
        "thread_id": thread_id,
        "session_id": session_id,
        "user_id": user_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "history": [],
    }
    _threads[session_id] = thread
    return thread


def append_to_thread(session_id: str, entry: dict[str, Any]) -> None:
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()

    thread = _threads.get(session_id)
    if thread is None:
        return

    thread["history"].append(entry)

    # Push to Backboard with memory="Auto" so important facts are persisted
    try:
        backboard_client.add_message(
            thread["thread_id"],
            __import__("json").dumps(entry, default=str),
            memory="Auto",
            send_to_llm="false",
        )
    except Exception:
        pass


def get_thread(session_id: str) -> dict[str, Any] | None:
    return _threads.get(session_id)


def clear_session(session_id: str) -> None:
    _threads.pop(session_id, None)


def clear_all() -> None:
    _threads.clear()
