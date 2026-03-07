"""Per-user persistent memory — SQLite-backed.

Stores user preferences and prior approval/denial history across restarts.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import config


def _conn() -> sqlite3.Connection:
    db_path = config.get_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_memory (
            user_id        TEXT PRIMARY KEY,
            preferences    TEXT NOT NULL DEFAULT '{}',
            history        TEXT NOT NULL DEFAULT '[]',
            denial_count   INTEGER NOT NULL DEFAULT 0,
            approval_count INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()


def get_user_memory(user_id: str) -> dict[str, Any]:
    with _conn() as conn:
        _init_db(conn)
        row = conn.execute(
            "SELECT * FROM user_memory WHERE user_id = ?", (user_id,)
        ).fetchone()
        if row:
            return {
                "preferences": json.loads(row["preferences"]),
                "history": json.loads(row["history"]),
                "denial_count": row["denial_count"],
                "approval_count": row["approval_count"],
            }
        conn.execute(
            "INSERT INTO user_memory (user_id) VALUES (?)", (user_id,)
        )
        conn.commit()
        return {"preferences": {}, "history": [], "denial_count": 0, "approval_count": 0}


def update_user_memory(user_id: str, decision_record: dict[str, Any]) -> None:
    with _conn() as conn:
        _init_db(conn)
        row = conn.execute(
            "SELECT history, denial_count, approval_count FROM user_memory WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if row is None:
            get_user_memory(user_id)
            row = conn.execute(
                "SELECT history, denial_count, approval_count FROM user_memory WHERE user_id = ?",
                (user_id,),
            ).fetchone()

        history = json.loads(row["history"])
        history.append(decision_record)

        status = decision_record.get("status", "")
        denial_count = row["denial_count"] + (1 if status == "blocked" else 0)
        approval_count = row["approval_count"] + (1 if status == "approved" else 0)

        conn.execute(
            "UPDATE user_memory SET history=?, denial_count=?, approval_count=? WHERE user_id=?",
            (json.dumps(history), denial_count, approval_count, user_id),
        )
        conn.commit()


def set_user_preference(user_id: str, key: str, value: Any) -> None:
    with _conn() as conn:
        _init_db(conn)
        row = conn.execute(
            "SELECT preferences FROM user_memory WHERE user_id = ?", (user_id,)
        ).fetchone()
        if row is None:
            get_user_memory(user_id)
            row = conn.execute(
                "SELECT preferences FROM user_memory WHERE user_id = ?", (user_id,)
            ).fetchone()
        prefs = json.loads(row["preferences"])
        prefs[key] = value
        conn.execute(
            "UPDATE user_memory SET preferences=? WHERE user_id=?",
            (json.dumps(prefs), user_id),
        )
        conn.commit()


def clear_all() -> None:
    with _conn() as conn:
        _init_db(conn)
        conn.execute("DELETE FROM user_memory")
        conn.commit()
