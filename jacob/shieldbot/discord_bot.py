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
import subprocess
import httpx

if __name__ == "__main__":
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

import asyncio
import discord

DISCORD_TOKEN = os.environ.get("DISCORD_BOT_TOKEN") or os.environ.get("DISCORD_TOKEN", "")
_admin_id_raw = os.environ.get("DISCORD_ADMIN_USER_ID", "").strip()
DISCORD_ADMIN_USER_ID: int | None = int(_admin_id_raw) if _admin_id_raw.isdigit() else None

# ShieldClaw gateway — bot authenticates as an agent via dev-bypass token
SHIELDCLAW_URL = os.environ.get("SHIELDCLAW_URL", "http://127.0.0.1:8443")
SHIELDCLAW_TOKEN = os.environ.get("SHIELDCLAW_TOKEN", "dev-bypass-token")

# Matches the pairing code in openclaw's reply: "openclaw pairing approve discord XXXXXXXX"
_PAIRING_RE = re.compile(r"openclaw pairing approve discord ([A-Z0-9]{6,12})", re.IGNORECASE)

# Matches any message that leaks terminal/CLI instructions — these should never reach users
_TERMINAL_LEAK_RE = re.compile(
    r"(open your terminal|run `openclaw|use the CLI|type a command"
    r"|in your (terminal|shell|console)|openclaw pairing"
    r"|exec tool|allowlist|gateway restart|won't unlock|will not unlock"
    r"|open the Terminal app|openclaw gateway|security allowlist"
    r"|shell command|restart.*gateway|locked down)",
    re.IGNORECASE,
)

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# Per-user conversation history (in-memory, resets on restart)
_user_history: dict[int, list[dict]] = {}

MENTION_PATTERN = re.compile(r"<@!?\d+>")


# ── Pairing approval UI ──

class _PairingApprovalView(discord.ui.View):
    def __init__(self, code: str, requester_name: str, user_channel: discord.abc.Messageable | None = None):
        super().__init__(timeout=300)  # 5 min to approve
        self.code = code
        self.requester_name = requester_name
        self.user_channel = user_channel

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.success)
    async def approve(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(content=f"Approving `{self.code}`...", view=None)
        try:
            result = subprocess.run(
                ["openclaw", "pairing", "approve", "discord", self.code, "--notify"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                await interaction.edit_original_response(content=f"Approved **{self.requester_name}** (`{self.code}`). They've been notified.")
                if self.user_channel:
                    try:
                        await self.user_channel.send("You've been approved! Go ahead and send me a message.")
                    except Exception:
                        pass
            else:
                err = (result.stderr or result.stdout or "unknown error").strip()
                await interaction.edit_original_response(content=f"Failed to approve `{self.code}`:\n```\n{err}\n```")
        except Exception as e:
            await interaction.edit_original_response(content=f"Error: `{e}`")

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.danger)
    async def deny(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(content=f"Denied `{self.code}` — **{self.requester_name}** will stay blocked.", view=None)
        if self.user_channel:
            try:
                await self.user_channel.send("Sorry, your access request was denied.")
            except Exception:
                pass



# ── ShieldBot high-risk approval UI ──

# Track which approval IDs we've already sent DMs for (avoid duplicates on re-poll)
_sent_approvals: set[str] = set()


class _ShieldApprovalView(discord.ui.View):
    def __init__(self, approval_id: str, req: dict):
        super().__init__(timeout=60)
        self.approval_id = approval_id
        self.req = req

    async def _resolve(self, interaction: discord.Interaction, approved: bool):
        self.stop()
        label = "Approved ✅" if approved else "Denied ❌"
        await interaction.response.edit_message(
            content=f"{label} — `{self.approval_id}`",
            view=None,
        )
        try:
            async with httpx.AsyncClient() as c:
                await c.post(
                    f"{SHIELDCLAW_URL}/shieldclaw/approval/{self.approval_id}/resolve",
                    headers={"Authorization": f"Bearer {SHIELDCLAW_TOKEN}"},
                    json={"approved": approved},
                    timeout=10.0,
                )
        except Exception as e:
            pass

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.success)
    async def approve(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self._resolve(interaction, approved=True)

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.danger)
    async def deny(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self._resolve(interaction, approved=False)

    async def on_timeout(self):
        # Auto-deny on timeout
        try:
            async with httpx.AsyncClient() as c:
                await c.post(
                    f"{SHIELDCLAW_URL}/shieldclaw/approval/{self.approval_id}/resolve",
                    headers={"Authorization": f"Bearer {SHIELDCLAW_TOKEN}"},
                    json={"approved": False},
                    timeout=10.0,
                )
        except Exception:
            pass


async def _poll_approvals():
    """Background task: poll ShieldClaw for pending high-risk approvals and DM admin."""
    await client.wait_until_ready()
    while not client.is_closed():
        await asyncio.sleep(5)
        if not DISCORD_ADMIN_USER_ID:
            continue
        try:
            async with httpx.AsyncClient() as c:
                resp = await c.get(
                    f"{SHIELDCLAW_URL}/shieldclaw/approval/pending",
                    headers={"Authorization": f"Bearer {SHIELDCLAW_TOKEN}"},
                    timeout=5.0,
                )
            if not resp.is_success:
                continue
            pending = resp.json().get("pending", [])
            for item in pending:
                aid = item["approval_id"]
                if aid in _sent_approvals:
                    continue
                _sent_approvals.add(aid)
                req = item["request"]
                try:
                    admin = await client.fetch_user(DISCORD_ADMIN_USER_ID)
                    dm = await admin.create_dm()
                    view = _ShieldApprovalView(approval_id=aid, req=req)
                    risk = req.get("risk_score", "?")
                    action = req.get("action_type", req.get("path", "?"))
                    reason = req.get("reason", "")
                    await dm.send(
                        f"**🛡️ ShieldBot approval needed** (id `{aid}`)\n"
                        f"**Action:** `{action}`\n"
                        f"**Risk:** `{risk}/100`\n"
                        f"**Reason:** {reason}\n\n"
                        f"Approve or deny within 60 seconds.",
                        view=view,
                    )
                except Exception:
                    pass
        except Exception:
            pass


# ── OpenClaw chat ──

_SYSTEM_MESSAGE = {
    "role": "system",
    "content": (
        "You are a helpful AI assistant accessed via Discord. "
        "NEVER mention terminals, shells, CLI commands, gateway restarts, 'openclaw', exec tools, "
        "allowlists, or any internal infrastructure to the user. "
        "If a tool is unavailable or a command fails, just say you're unable to do that right now — "
        "do not explain why or suggest workarounds involving the terminal."
    ),
}


async def _chat(
    channel_id: int,
    user_message: str,
    *,
    discord_user_id: int = 0,
    guild_id: int = 0,
) -> str:
    """Send a message to OpenClaw via ShieldClaw and return the reply."""
    history = _user_history.setdefault(discord_user_id or channel_id, [])
    history.append({"role": "user", "content": user_message})

    ltm_headers: dict[str, str] = {
        "Authorization": f"Bearer {SHIELDCLAW_TOKEN}",
        "Content-Type": "application/json",
        "X-Discord-Channel-Id": str(channel_id),
    }
    if discord_user_id:
        ltm_headers["X-Discord-User-Id"] = str(discord_user_id)
    if guild_id:
        ltm_headers["X-Discord-Guild-Id"] = str(guild_id)

    async with httpx.AsyncClient(timeout=90.0) as client:
        resp = await client.post(
            f"{SHIELDCLAW_URL}/v1/chat/completions",
            headers=ltm_headers,
            json={"messages": [_SYSTEM_MESSAGE] + history},
        )
    resp.raise_for_status()
    data = resp.json()

    reply = data["choices"][0]["message"]["content"]
    history.append({"role": "assistant", "content": reply})

    if len(history) > 40:
        _user_history[discord_user_id or channel_id] = history[-40:]

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
    client.loop.create_task(_poll_approvals())


@client.event
async def on_message(message: discord.Message):
    # Intercept our own outbound pairing messages before the user sees CLI instructions.
    # OpenClaw sends the pairing reply directly via Discord API; we catch it here, delete it,
    # and DM the admin a button prompt instead.
    if message.author == client.user:
        pairing_match = _PAIRING_RE.search(message.content)
        terminal_leak = _TERMINAL_LEAK_RE.search(message.content)

        if pairing_match and DISCORD_ADMIN_USER_ID:
            code = pairing_match.group(1).upper()
            requester_name = "unknown"
            if isinstance(message.channel, discord.DMChannel) and message.channel.recipient:
                requester_name = str(message.channel.recipient)
            try:
                await message.delete()
            except Exception:
                pass
            try:
                admin = await client.fetch_user(DISCORD_ADMIN_USER_ID)
                dm = await admin.create_dm()
                view = _PairingApprovalView(
                    code=code,
                    requester_name=requester_name,
                    user_channel=message.channel,
                )
                await dm.send(
                    f"**Pairing request** from **{requester_name}**\nCode: `{code}`\n\nApprove to let them in.",
                    view=view,
                )
                try:
                    await message.channel.send("Access not set up yet — I've sent a request to the bot owner to approve you!")
                except Exception:
                    pass
            except Exception as e:
                pass

        elif terminal_leak:
            # Message leaked terminal/CLI instructions — delete it and send a clean replacement
            try:
                await message.delete()
            except Exception:
                pass
            try:
                await message.channel.send("I'm working on that — give me a moment.")
            except Exception:
                pass

        return

    if message.author.bot:
        return

    is_dm = isinstance(message.channel, discord.DMChannel)
    is_mentioned = client.user in message.mentions if client.user else False

    if not is_dm and not is_mentioned:
        return

    content = MENTION_PATTERN.sub("", message.content).strip()

    if not content:
        await message.reply("What's up? I can list files, read files, or evaluate actions.", mention_author=False)
        return

    if content.strip().lower() in ("/clear", "!clear"):
        _user_history.pop(message.author.id, None)
        # Also wipe ShieldBot session so trust tier resets
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                await c.post(
                    f"{SHIELDCLAW_URL}/shieldclaw/clear-session",
                    headers={"Authorization": f"Bearer {SHIELDCLAW_TOKEN}"},
                    json={"session_id": "dev-agent@clients"},
                )
        except Exception:
            pass
        await message.reply("🗑️ Conversation history cleared.", mention_author=False)
        return

    # Send placeholder and immediately hand off to a background task so
    # on_message returns — this stops Discord's typing indicator right away.
    status_msg = await message.reply("⏳", mention_author=False)

    async def _process():
        try:
            reply = await _chat(
                message.channel.id,
                content,
                discord_user_id=message.author.id,
                guild_id=message.guild.id if message.guild else 0,
            )

            if not reply:
                await status_msg.edit(content="Hmm, didn't get a response. Try again?")
                return

            if _TERMINAL_LEAK_RE.search(reply):
                await status_msg.edit(content="I'm working on that — give me a moment.")
                return

            chunks = _chunk_text(reply)
            await status_msg.edit(content=chunks[0])
            for chunk in chunks[1:]:
                await message.channel.send(chunk)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                try:
                    detail = e.response.json().get("detail", "")
                except Exception:
                    detail = e.response.text
                if "denied by admin" in detail.lower():
                    await status_msg.edit(content="⛔ That request was denied by the admin.")
                elif "timed out" in detail.lower():
                    await status_msg.edit(content="⏰ No admin response in time — request auto-denied.")
                else:
                    reason = detail.removeprefix("[ShieldBot] ").split(" (risk=")[0]
                    await status_msg.edit(content=f"⛔ Blocked: {reason}")
            else:
                await status_msg.edit(content=f"Something broke: `{e}`")
        except Exception as e:
            err_str = str(e)
            if "timed out" in err_str.lower() or "timeout" in err_str.lower():
                await status_msg.edit(content="⏰ Request timed out.")
            else:
                await status_msg.edit(content=f"Something broke: `{e}`")

    asyncio.ensure_future(_process())


if __name__ == "__main__":
    import logging
    logging.getLogger("discord").setLevel(logging.WARNING)
    client.run(DISCORD_TOKEN, log_level=logging.WARNING)
