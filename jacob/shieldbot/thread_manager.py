"""Thread manager — real Backboard.io threads.

Every session gets a real persistent thread on Backboard.io.
Events are posted as messages with memory=Auto so Backboard
automatically extracts and stores relevant facts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from . import backboard_client

# Maps session_id → backboard thread_id
_session_map: dict[str, str] = {}

# Local mirror of history (for fast in-process reads)
_local_history: dict[str, list[dict[str, Any]]] = {}


def get_or_create_thread(session_id: str, user_id: str) -> dict[str, Any]:
    if session_id in _session_map:
        return {
            "thread_id": _session_map[session_id],
            "session_id": session_id,
            "user_id": user_id,
            "history": _local_history.get(session_id, []),
        }

    result = backboard_client.create_thread()
    thread_id = result["thread_id"]
    _session_map[session_id] = thread_id
    _local_history[session_id] = []

    # Post an init message so the thread has context
    backboard_client.add_message(
        thread_id,
        json.dumps({"event": "thread_created", "user_id": user_id, "session_id": session_id}),
        memory="Auto",
        send_to_llm="false",
    )

    return {
        "thread_id": thread_id,
        "session_id": session_id,
        "user_id": user_id,
        "history": [],
    }


def append_to_thread(session_id: str, entry: dict[str, Any]) -> None:
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Local mirror
    _local_history.setdefault(session_id, []).append(entry)

    # Push to Backboard
    if session_id in _session_map:
        thread_id = _session_map[session_id]
        backboard_client.add_message(
            thread_id,
            json.dumps(entry, default=str),
            memory="Auto",
            send_to_llm="false",
        )


def get_thread(session_id: str) -> dict[str, Any] | None:
    if session_id not in _session_map:
        return None
    return {
        "thread_id": _session_map[session_id],
        "session_id": session_id,
        "history": _local_history.get(session_id, []),
    }


def clear_all() -> None:
    _session_map.clear()
    _local_history.clear()
