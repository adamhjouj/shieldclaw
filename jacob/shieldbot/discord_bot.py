#!/usr/bin/env python3
"""Shieldbot Discord bot — OpenClaw-style chat interface.

Talk to the bot by @mentioning it in a channel or DMing it directly.
Responses are plain conversational text routed through Backboard.io.
"""

from __future__ import annotations

import sys
import os
import json
import re

if __name__ == "__main__":
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import discord

from jacob.shieldbot import backboard_client

DISCORD_TOKEN = "MTQzNjQ2MjEwMTAwMTUzOTYxNQ.GXB94T.zjvIhgwLXzUCyP2SObfuEvTSpARyu1rN8ZewJk"

SYSTEM_PROMPT = """You are Shieldbot — a security reviewer for an AI agent system called OpenClaw.

Your personality:
- Be genuinely helpful, not performatively helpful. Skip "Great question!" filler.
- Have opinions. If something is risky, say so directly.
- Be concise. One short paragraph for the reasoning, then the verdict.
- Use a casual but professional tone — like a sharp security engineer on your team.

When a user describes an action (purchase, file share, data export, deployment, shell command, email, etc.):
1. Think about the risk
2. Give your assessment in plain English
3. End with a clear verdict line like:

**Verdict:** ✅ Approved (risk 15/100)
or
**Verdict:** ⚠️ Needs confirmation (risk 55/100) — [reason]
or
**Verdict:** 🛑 Blocked (risk 90/100) — [reason]

If the user is just chatting or asking questions, respond normally — no verdict needed.
Remember context from the conversation. If they ask follow-ups about a previous action, use what you know."""

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# Backboard thread per Discord channel for persistent conversation memory
_channel_threads: dict[int, str] = {}

MENTION_PATTERN = re.compile(r"<@!?\d+>")


def _get_or_create_thread(channel_id: int) -> str:
    if channel_id in _channel_threads:
        return _channel_threads[channel_id]

    thread = backboard_client.create_thread()
    thread_id = thread["thread_id"]
    _channel_threads[channel_id] = thread_id

    backboard_client.add_message(
        thread_id, SYSTEM_PROMPT,
        memory="Auto", send_to_llm="false",
    )
    return thread_id


def _chunk_text(text: str, limit: int = 2000) -> list[str]:
    """Split text into chunks that fit Discord's message limit."""
    if len(text) <= limit:
        return [text]
    chunks = []
    while text:
        if len(text) <= limit:
            chunks.append(text)
            break
        split_at = text.rfind("\n", 0, limit)
        if split_at == -1:
            split_at = text.rfind(" ", 0, limit)
        if split_at == -1:
            split_at = limit
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    return chunks


@client.event
async def on_ready():
    print(f"[shieldbot] Logged in as {client.user}")
    print(f"[shieldbot] Backboard.io: CONNECTED → {backboard_client.BASE_URL}")
    print(f"[shieldbot] @mention me in a channel or DM me directly")


@client.event
async def on_message(message: discord.Message):
    if message.author == client.user or message.author.bot:
        return

    is_dm = isinstance(message.channel, discord.DMChannel)
    is_mentioned = client.user in message.mentions if client.user else False

    # OpenClaw style: require mention in guilds, respond freely in DMs
    if not is_dm and not is_mentioned:
        return

    content = MENTION_PATTERN.sub("", message.content).strip()
    if not content:
        await message.reply("What's up? Describe an action and I'll tell you if it's safe.")
        return

    async with message.channel.typing():
        try:
            thread_id = _get_or_create_thread(message.channel.id)

            resp = backboard_client.add_message(
                thread_id, content,
                memory="Auto", send_to_llm="true",
            )

            reply = resp.get("content", "")
            if not reply:
                await message.reply("Hmm, didn't get a response. Try again?")
                return

            for chunk in _chunk_text(reply):
                await message.reply(chunk)

        except Exception as e:
            print(f"[shieldbot] Error: {e}")
            await message.reply(f"Something broke: `{e}`")


if __name__ == "__main__":
    print("[shieldbot] Starting Shieldbot...")
    client.run(DISCORD_TOKEN)
