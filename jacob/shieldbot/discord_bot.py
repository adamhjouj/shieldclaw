#!/usr/bin/env python3
"""Shieldbot Discord bot — routes all chat through OpenClaw via ShieldClaw.

Talk to the bot by @mentioning it in a channel or DMing it directly.
All messages are proxied to OpenClaw's /v1/chat/completions endpoint,
which has Claude, tools, and memory built in.
"""

from __future__ import annotations

import sys
import os
import re
import httpx

if __name__ == "__main__":
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import discord

DISCORD_TOKEN = os.environ.get("DISCORD_TOKEN", "")

# ShieldClaw gateway — bot authenticates as an agent via dev-bypass token
SHIELDCLAW_URL = os.environ.get("SHIELDCLAW_URL", "http://127.0.0.1:8443")
SHIELDCLAW_TOKEN = os.environ.get("SHIELDCLAW_TOKEN", "dev-bypass-token")

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# Per-channel conversation history (in-memory, resets on restart)
_channel_history: dict[int, list[dict]] = {}

MENTION_PATTERN = re.compile(r"<@!?\d+>")


# ── OpenClaw chat ──

def _chat(channel_id: int, user_message: str) -> str:
    """Send a message to OpenClaw via ShieldClaw and return the reply."""
    history = _channel_history.setdefault(channel_id, [])
    history.append({"role": "user", "content": user_message})

    resp = httpx.post(
        f"{SHIELDCLAW_URL}/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {SHIELDCLAW_TOKEN}",
            "Content-Type": "application/json",
        },
        json={"messages": history},
        timeout=60.0,
    )
    resp.raise_for_status()
    data = resp.json()

    reply = data["choices"][0]["message"]["content"]
    history.append({"role": "assistant", "content": reply})

    if len(history) > 40:
        _channel_history[channel_id] = history[-40:]

    return reply


# ── Discord text chunking ──

def _chunk_text(text: str, limit: int = 2000) -> list[str]:
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


# ── Discord events ──

@client.event
async def on_ready():
    print(f"[shieldbot] Logged in as {client.user}")
    print(f"[shieldbot] OpenClaw gateway: {SHIELDCLAW_URL}")
    print(f"[shieldbot] @mention me in a channel or DM me directly")


@client.event
async def on_message(message: discord.Message):
    if message.author == client.user or message.author.bot:
        return

    is_dm = isinstance(message.channel, discord.DMChannel)
    is_mentioned = client.user in message.mentions if client.user else False

    if not is_dm and not is_mentioned:
        return

    content = MENTION_PATTERN.sub("", message.content).strip()
    print(f"[shieldbot] {message.author}: '{content}'")

    if not content:
        await message.reply("What's up? I can list files, read files, or evaluate actions.", mention_author=False)
        return

    async with message.channel.typing():
        try:
            reply = _chat(message.channel.id, content)

            if not reply:
                await message.reply("Hmm, didn't get a response. Try again?", mention_author=False)
                return

            chunks = _chunk_text(reply)
            await message.reply(chunks[0], mention_author=False)
            for chunk in chunks[1:]:
                await message.channel.send(chunk)

        except Exception as e:
            print(f"[shieldbot] Error: {e}")
            await message.reply(f"Something broke: `{e}`", mention_author=False)


if __name__ == "__main__":
    print("[shieldbot] Starting Shieldbot...")
    client.run(DISCORD_TOKEN)
