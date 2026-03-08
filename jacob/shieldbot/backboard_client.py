"""Backboard.io client — per-user assistants with native memory.

One Backboard assistant is created per Discord user ID. memory="Auto" on every
message means Backboard automatically extracts, stores, and injects memories —
no manual SQLite reads/writes needed.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
from typing import Any

from backboard import BackboardClient

API_KEY = os.environ.get("BACKBOARDS_API_KEY", "")
ASSISTANT_ID: str | None = None  # auto-created on first use

_client: BackboardClient | None = None

# Cache: user_id -> assistant_id
_user_assistants: dict[str, str] = {}


def _get_client() -> BackboardClient:
    global _client
    if _client is None:
        _client = BackboardClient(api_key=API_KEY)
    return _client


def _run(coro) -> Any:
    """Run an async coroutine from sync context.

    Runs in a dedicated background thread with its own event loop so we never
    interfere with uvicorn's loop (which nest_asyncio would break).
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def is_configured() -> bool:
    return bool(API_KEY)


def _get_default_assistant_id() -> str:
    """Get or create the default shared assistant."""
    global ASSISTANT_ID
    if ASSISTANT_ID:
        return ASSISTANT_ID

    async def _create():
        client = _get_client()
        return await client.create_assistant(
            name="shieldbot-default",
            system_prompt="You are ShieldBot's shared memory layer.",
        )

    assistant = _run(_create())
    ASSISTANT_ID = assistant.assistant_id
    return ASSISTANT_ID


# ── Per-user assistants ──

async def _get_or_create_user_assistant(user_id: str) -> str:
    """Get or create a Backboard assistant for this user. Cached in memory."""
    if user_id in _user_assistants:
        return _user_assistants[user_id]

    client = _get_client()
    assistant = await client.create_assistant(
        name=f"shieldbot-user-{user_id}",
        system_prompt=(
            "You are ShieldBot's memory layer for a specific user. "
            "Remember their approval/denial history, preferences, and behavioral patterns "
            "to help evaluate future AI agent actions."
        ),
    )
    _user_assistants[user_id] = assistant.assistant_id
    return assistant.assistant_id


def get_or_create_user_assistant(user_id: str) -> str:
    return _run(_get_or_create_user_assistant(user_id))


# ── Threads ──

async def _create_thread(assistant_id: str) -> dict[str, Any]:
    client = _get_client()
    thread = await client.create_thread(assistant_id)
    return {"thread_id": thread.thread_id}


def create_thread(user_id: str | None = None) -> dict[str, Any]:
    if user_id:
        assistant_id = get_or_create_user_assistant(user_id)
    else:
        assistant_id = _get_default_assistant_id()
    return _run(_create_thread(assistant_id))


# ── Messages with native memory ──

async def _add_message(thread_id: str, content: str, memory: str, send_to_llm: bool) -> dict[str, Any]:
    client = _get_client()
    response = await client.add_message(
        thread_id=thread_id,
        content=content,
        memory=memory,
        stream=False,
    )
    return {"content": getattr(response, "content", ""), "raw": response}


def add_message(
    thread_id: str,
    content: str,
    *,
    memory: str = "Auto",
    send_to_llm: str = "false",
) -> dict[str, Any]:
    return _run(_add_message(thread_id, content, memory, send_to_llm == "true"))


# ── Memories ──

async def _list_memories(assistant_id: str) -> dict[str, Any]:
    client = _get_client()
    result = await client.list_memories(assistant_id)
    return result if isinstance(result, dict) else {"memories": result}


def list_memories(user_id: str | None = None) -> dict[str, Any]:
    assistant_id = _user_assistants.get(user_id or "", "") or _get_default_assistant_id()
    return _run(_list_memories(assistant_id))


async def _add_memory_direct(assistant_id: str, content: str, metadata: dict | None) -> dict[str, Any]:
    client = _get_client()
    result = await client.add_memory(assistant_id=assistant_id, content=content)
    return result if isinstance(result, dict) else {"status": "ok"}


def add_memory(content: str, metadata: dict | None = None, user_id: str | None = None) -> dict[str, Any]:
    assistant_id = _user_assistants.get(user_id or "", "") or _get_default_assistant_id()
    return _run(_add_memory_direct(assistant_id, content, metadata))


def get_thread(thread_id: str) -> dict[str, Any]:
    async def _get():
        client = _get_client()
        result = await client.get_thread(thread_id)
        return result if isinstance(result, dict) else {"thread_id": thread_id}
    return _run(_get())


def list_threads(user_id: str | None = None) -> list[dict[str, Any]]:
    async def _list():
        assistant_id = _user_assistants.get(user_id or "", "") or _get_default_assistant_id()
        client = _get_client()
        result = await client.list_threads(assistant_id)
        return result if isinstance(result, list) else []
    return _run(_list())


def get_memory_stats(user_id: str | None = None) -> dict[str, Any]:
    return {"user_id": user_id, "assistants_cached": len(_user_assistants)}


def close() -> None:
    global _client
    _client = None
