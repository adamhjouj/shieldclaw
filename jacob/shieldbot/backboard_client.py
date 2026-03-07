"""Backboard.io API client — real integration.

API docs: https://docs.backboard.io
Base URL: https://app.backboard.io/api
Auth: X-API-Key header
"""

from __future__ import annotations

import json
from typing import Any

import httpx

API_KEY = "espr_JwYIxHoAqAcO9Y775yV5fxggdeNqUYRCapmc4bHb460"
BASE_URL = "https://app.backboard.io/api"
ASSISTANT_ID = "1cd289f2-0a4b-4974-b486-46b4c735c1e5"

_client: httpx.Client | None = None


def _get_client() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(
            base_url=BASE_URL,
            headers={"X-API-Key": API_KEY},
            timeout=30.0,
        )
    return _client


def is_configured() -> bool:
    return bool(API_KEY)


# ── Assistants ──

def create_assistant(name: str, system_prompt: str) -> dict[str, Any]:
    resp = _get_client().post("/assistants", json={
        "name": name,
        "system_prompt": system_prompt,
    })
    resp.raise_for_status()
    return resp.json()


def list_assistants() -> list[dict[str, Any]]:
    resp = _get_client().get("/assistants")
    resp.raise_for_status()
    return resp.json()


# ── Threads ──

def create_thread() -> dict[str, Any]:
    resp = _get_client().post(f"/assistants/{ASSISTANT_ID}/threads", json={})
    resp.raise_for_status()
    return resp.json()


def get_thread(thread_id: str) -> dict[str, Any]:
    resp = _get_client().get(f"/threads/{thread_id}")
    resp.raise_for_status()
    return resp.json()


def list_threads() -> list[dict[str, Any]]:
    resp = _get_client().get(f"/assistants/{ASSISTANT_ID}/threads")
    resp.raise_for_status()
    return resp.json()


# ── Messages ──

def add_message(
    thread_id: str,
    content: str,
    *,
    memory: str = "Auto",
    send_to_llm: str = "false",
) -> dict[str, Any]:
    resp = _get_client().post(
        f"/threads/{thread_id}/messages",
        data={
            "content": content,
            "stream": "false",
            "memory": memory,
            "send_to_llm": send_to_llm,
        },
    )
    resp.raise_for_status()
    return resp.json()


# ── Memories ──

def list_memories() -> dict[str, Any]:
    resp = _get_client().get(f"/assistants/{ASSISTANT_ID}/memories")
    resp.raise_for_status()
    return resp.json()


def add_memory(content: str, metadata: dict | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"content": content}
    if metadata:
        body["metadata"] = metadata
    resp = _get_client().post(f"/assistants/{ASSISTANT_ID}/memories", json=body)
    resp.raise_for_status()
    return resp.json()


def submit_tool_outputs(thread_id: str, run_id: str, tool_outputs: list[dict[str, str]]) -> dict[str, Any]:
    resp = _get_client().post(
        f"/threads/{thread_id}/runs/{run_id}/submit-tool-outputs",
        json={"tool_outputs": tool_outputs},
    )
    resp.raise_for_status()
    return resp.json()


def get_memory_stats() -> dict[str, Any]:
    resp = _get_client().get(f"/assistants/{ASSISTANT_ID}/memories/stats")
    resp.raise_for_status()
    return resp.json()


def close() -> None:
    global _client
    if _client is not None:
        _client.close()
        _client = None
