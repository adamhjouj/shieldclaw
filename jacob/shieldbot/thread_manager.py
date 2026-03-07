"""Backboard-style thread manager — SQLite-backed.

Threads provide per-task/session context for Shieldbot evaluations.
Persists across process restarts via a local SQLite database.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from . import config


def _conn() -> sqlite3.Connection:
    db_path = config.get_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threads (
            session_id  TEXT PRIMARY KEY,
            thread_id   TEXT NOT NULL,
            user_id     TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            history     TEXT NOT NULL DEFAULT '[]'
        )
    """)
    conn.commit()


def get_or_create_thread(session_id: str, user_id: str) -> dict[str, Any]:
    with _conn() as conn:
        _init_db(conn)
        row = conn.execute(
            "SELECT * FROM threads WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row:
            return {
                "thread_id": row["thread_id"],
                "session_id": row["session_id"],
                "user_id": row["user_id"],
                "created_at": row["created_at"],
                "history": json.loads(row["history"]),
            }
        thread = {
            "thread_id": str(uuid.uuid4()),
            "session_id": session_id,
            "user_id": user_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "history": [],
        }
        conn.execute(
            "INSERT INTO threads (session_id, thread_id, user_id, created_at, history) VALUES (?,?,?,?,?)",
            (session_id, thread["thread_id"], user_id, thread["created_at"], "[]"),
        )
        conn.commit()
        return thread


def append_to_thread(session_id: str, entry: dict[str, Any]) -> None:
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    with _conn() as conn:
        _init_db(conn)
        row = conn.execute(
            "SELECT history FROM threads WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return
        history = json.loads(row["history"])
        history.append(entry)
        conn.execute(
            "UPDATE threads SET history = ? WHERE session_id = ?",
            (json.dumps(history), session_id),
        )
        conn.commit()


def get_thread(session_id: str) -> dict[str, Any] | None:
    with _conn() as conn:
        _init_db(conn)
        row = conn.execute(
            "SELECT * FROM threads WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        return {
            "thread_id": row["thread_id"],
            "session_id": row["session_id"],
            "user_id": row["user_id"],
            "created_at": row["created_at"],
            "history": json.loads(row["history"]),
        }


def clear_all() -> None:
    with _conn() as conn:
        _init_db(conn)
        conn.execute("DELETE FROM threads")
        conn.commit()
