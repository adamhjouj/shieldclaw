"""
ShieldClaw Discord Onboarding Bot

When a new user joins the server (or types /register), Clawdbot starts a
natural-language conversation to figure out what they want to use it for,
then infers the right permission scopes and registers them as a ShieldClaw agent.

Setup:
    pip install discord.py httpx anthropic python-dotenv

Required env vars:
    DISCORD_BOT_TOKEN      — Discord bot token
    SHIELDCLAW_URL         — e.g. http://localhost:8443
    SHIELDCLAW_ADMIN_TOKEN — Bearer token with gateway:admin scope (or use DEV_BYPASS)
    ANTHROPIC_API_KEY      — For policy inference

Run:
    python discord_onboarding.py
"""

import asyncio
import json
import logging
import os
import re

import anthropic
import discord
import httpx
from discord import app_commands
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("clawdbot.onboarding")

DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
SHIELDCLAW_URL = os.getenv("SHIELDCLAW_URL", "http://localhost:8443")
SHIELDCLAW_ADMIN_TOKEN = os.getenv("SHIELDCLAW_ADMIN_TOKEN", "dev-bypass-token")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

VALID_SCOPES = [
    "gateway:read",
    "gateway:message",
    "gateway:tools",
    "gateway:canvas",
    "gateway:tools:exec",
    "gateway:admin",
]
VALID_DATA_ACCESS = ["credentials", "pii", "infra", "financial", "env_config"]

# ---------------------------------------------------------------------------
# Onboarding conversation questions
# ---------------------------------------------------------------------------

ONBOARDING_QUESTIONS = [
    "What are you planning to use Clawdbot for? (e.g. answering questions, running automations, managing files...)",
    "Will it need to send or receive messages on your behalf, or mostly just look things up?",
    "Does it need access to any sensitive data like passwords, emails, financial info, or server credentials?",
]

ONBOARDING_SYSTEM_PROMPT = """You are Clawdbot, an AI assistant onboarding a new user to ShieldClaw.
Your job is to have a friendly, concise conversation to understand what the user wants to use their AI agent for.
Ask one question at a time. Be warm and brief. Do not use technical jargon like "scopes" or "OAuth".
After 3 user replies, you will summarize what you've learned — but don't do that yet, just ask the next question naturally.
"""

POLICY_INFERENCE_SYSTEM_PROMPT = """You are a security policy parser for ShieldClaw, an OAuth proxy for AI agents.

Read the conversation between Clawdbot and a new user. Infer the minimum necessary permissions.

VALID SCOPES (increasing risk):
- gateway:read       — Read-only status/probe access. Low risk.
- gateway:message    — Send and receive messages (chat). Medium risk.
- gateway:tools      — Invoke tool calls (automations, actions). Medium risk.
- gateway:canvas     — Canvas/UI display access. Low risk.
- gateway:tools:exec — Execute arbitrary shell commands. CRITICAL — only if user explicitly wants command execution.
- gateway:admin      — Full admin access. CRITICAL — almost never needed.

VALID DATA_ACCESS CATEGORIES:
- credentials  — Passwords, API keys, tokens, secrets
- pii          — SSNs, emails, credit cards, phone numbers
- infra        — Database URLs, connection strings, internal IPs
- financial    — Bank accounts, balances, financial identifiers
- env_config   — Cloud credentials, service API keys

RULES:
1. Principle of least privilege — only grant what was clearly described.
2. Never grant gateway:tools:exec or gateway:admin unless explicitly requested.
3. Only grant data_access categories explicitly mentioned by the user.
4. If unclear, default to gateway:read only with no data_access.

Return ONLY valid JSON matching this schema exactly:
{
  "scopes": ["<scope>", ...],
  "data_access": ["<category>", ...],
  "confidence": "high" | "medium" | "low",
  "reasoning": "<one sentence>",
  "warnings": ["<warning>", ...]
}"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _infer_permissions_from_conversation(history: list[dict]) -> dict:
    """Send the full onboarding conversation to Claude and get back inferred scopes."""
    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)

    conversation_text = "\n".join(
        f"{'Clawdbot' if m['role'] == 'assistant' else 'User'}: {m['content']}"
        for m in history
    )

    try:
        resp = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            temperature=0,
            system=POLICY_INFERENCE_SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": (
                    f"Here is the onboarding conversation:\n\n{conversation_text}\n\n"
                    "Infer the minimum necessary permissions. Return only valid JSON."
                ),
            }],
        )
        raw = resp.content[0].text.strip()
        parsed = json.loads(raw)

        # Sanitise — strip anything not in our known-good lists
        return {
            "scopes": [s for s in parsed.get("scopes", []) if s in VALID_SCOPES] or ["gateway:read"],
            "data_access": [d for d in parsed.get("data_access", []) if d in VALID_DATA_ACCESS],
            "confidence": parsed.get("confidence", "low") if parsed.get("confidence") in ("high", "medium", "low") else "low",
            "reasoning": str(parsed.get("reasoning", ""))[:400],
            "warnings": [str(w) for w in parsed.get("warnings", [])][:5],
        }
    except Exception as e:
        log.warning(f"Permission inference failed: {e}")
        return {
            "scopes": ["gateway:read"],
            "data_access": [],
            "confidence": "low",
            "reasoning": "Could not infer permissions; defaulted to read-only.",
            "warnings": [str(e)],
        }


async def _register_agent(agent_name: str, scopes: list[str], data_access: list[str], owner_discord_id: str) -> dict:
    """POST to ShieldClaw /shieldclaw/agents to create the agent."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{SHIELDCLAW_URL}/shieldclaw/agents",
            headers={"Authorization": f"Bearer {SHIELDCLAW_ADMIN_TOKEN}"},
            json={
                "agent_name": agent_name,
                "description": f"Discord onboarding agent for user {owner_discord_id}",
                "scopes": scopes,
                "data_access": data_access,
            },
        )
        resp.raise_for_status()
        return resp.json()


def _format_permissions_summary(inferred: dict) -> str:
    scope_lines = "\n".join(f"  • `{s}`" for s in inferred["scopes"])
    data_lines = "\n".join(f"  • `{d}`" for d in inferred["data_access"]) if inferred["data_access"] else "  • *(none — no sensitive data access)*"
    warnings = ""
    if inferred["warnings"]:
        warnings = "\n\n⚠️ **Heads up:** " + " | ".join(inferred["warnings"])

    return (
        f"**Based on what you told me, here's what I'd set up:**\n\n"
        f"**Permissions:**\n{scope_lines}\n\n"
        f"**Sensitive data access:**\n{data_lines}\n\n"
        f"*Confidence: {inferred['confidence']} — {inferred['reasoning']}*"
        f"{warnings}\n\n"
        f"Does this look right? Reply **yes** to register, **no** to restart, "
        f"or describe any changes you'd like."
    )


# ---------------------------------------------------------------------------
# Active onboarding sessions: user_id → session state
# ---------------------------------------------------------------------------

_sessions: dict[int, dict] = {}
# session shape:
# {
#   "history": [{"role": "assistant"|"user", "content": str}],
#   "question_index": int,           # which of ONBOARDING_QUESTIONS we're on
#   "inferred": dict | None,         # result from inference, set after Q3
#   "awaiting_confirm": bool,
# }


# ---------------------------------------------------------------------------
# Bot setup
# ---------------------------------------------------------------------------

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = discord.Client(intents=intents)
tree = app_commands.CommandTree(bot)


async def _start_onboarding(user: discord.User | discord.Member):
    """Open a DM and fire the first onboarding message."""
    first_q = ONBOARDING_QUESTIONS[0]
    _sessions[user.id] = {
        "history": [{"role": "assistant", "content": f"Hi! What are you using Clawdbot for?\n{first_q}"}],
        "question_index": 1,
        "inferred": None,
        "awaiting_confirm": False,
    }
    try:
        dm = await user.create_dm()
        await dm.send(
            f"👋 **Hi! I'm Clawdbot.**\n\n"
            f"I just need to ask you a couple of quick questions so I can set up the right permissions for your account.\n\n"
            f"**{first_q}**"
        )
    except discord.Forbidden:
        log.warning(f"Cannot DM user {user.id} — DMs may be closed")


async def _handle_onboarding_reply(message: discord.Message):
    """Handle a DM reply from a user currently in onboarding."""
    uid = message.author.id
    session = _sessions.get(uid)
    if session is None:
        return

    user_text = message.content.strip()
    session["history"].append({"role": "user", "content": user_text})

    # --- Confirmation step ---
    if session["awaiting_confirm"]:
        low = user_text.lower()
        if low in ("yes", "y", "yeah", "yep", "yup", "looks good", "correct", "ok", "okay"):
            await _do_register(message, session)
        elif low in ("no", "n", "nope", "restart", "redo"):
            del _sessions[uid]
            await _start_onboarding(message.author)
        else:
            # Treat as a correction — re-infer with the extra context appended
            await message.channel.send("Got it, let me adjust based on that...")
            inferred = await _infer_permissions_from_conversation(session["history"])
            session["inferred"] = inferred
            await message.channel.send(_format_permissions_summary(inferred))
        return

    # --- Still in questioning phase ---
    qi = session["question_index"]
    if qi < len(ONBOARDING_QUESTIONS):
        next_q = ONBOARDING_QUESTIONS[qi]
        session["question_index"] += 1
        session["history"].append({"role": "assistant", "content": next_q})
        await message.channel.send(f"**{next_q}**")
    else:
        # All questions answered — infer permissions
        await message.channel.send("Great, give me a moment while I figure out the right permissions...")
        inferred = await _infer_permissions_from_conversation(session["history"])
        session["inferred"] = inferred
        session["awaiting_confirm"] = True
        await message.channel.send(_format_permissions_summary(inferred))


async def _do_register(message: discord.Message, session: dict):
    """Actually call ShieldClaw to register the agent and send the result."""
    uid = message.author.id
    inferred = session["inferred"]
    agent_name = f"discord-{message.author.name}-{uid}"

    await message.channel.send("⏳ Registering your agent with ShieldClaw...")

    try:
        result = await _register_agent(
            agent_name=agent_name,
            scopes=inferred["scopes"],
            data_access=inferred["data_access"],
            owner_discord_id=str(uid),
        )

        scope_list = ", ".join(f"`{s}`" for s in result.get("scopes", []))
        await message.channel.send(
            f"✅ **You're all set!**\n\n"
            f"**Agent ID:** `{result['agent_id']}`\n"
            f"**Permissions granted:** {scope_list}\n\n"
            f"Your agent is active and ready to use.\n\n"
            f"**Client credentials** (save these — they won't be shown again):\n"
            f"Client ID: ||`{result['client_id']}`||\n"
            f"Client Secret: ||`{result['client_secret']}`||"
        )
        log.info(f"Registered agent {result['agent_id']} for Discord user {uid}")
    except httpx.HTTPStatusError as e:
        await message.channel.send(
            f"❌ Registration failed: `{e.response.status_code}` — {e.response.text[:200]}"
        )
        log.error(f"Agent registration failed for {uid}: {e}")
    except Exception as e:
        await message.channel.send(f"❌ Something went wrong: {e}")
        log.error(f"Agent registration error for {uid}: {e}")
    finally:
        _sessions.pop(uid, None)


# ---------------------------------------------------------------------------
# Bot events
# ---------------------------------------------------------------------------

@bot.event
async def on_ready():
    await tree.sync()
    log.info(f"Clawdbot online as {bot.user} — onboarding ready")


@bot.event
async def on_member_join(member: discord.Member):
    """Auto-start onboarding when someone joins the server."""
    await _start_onboarding(member)


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return
    # Only handle DMs for onboarding replies
    if isinstance(message.channel, discord.DMChannel) and message.author.id in _sessions:
        await _handle_onboarding_reply(message)


# ---------------------------------------------------------------------------
# Pending Discord approval requests
# Populated by main.py when ShieldBot returns needs_confirmation.
# Resolved when the user clicks Approve / Deny in Discord.
# ---------------------------------------------------------------------------

_pending_confirmations: dict[str, asyncio.Future] = {}
_ADMIN_DISCORD_USER_ID: int | None = int(os.getenv("DISCORD_ADMIN_USER_ID", "0")) or None


async def request_discord_approval(
    request_id: str,
    agent_name: str,
    action_type: str,
    reason: str,
    risk_score: float,
    factors: list,
) -> bool:
    """
    DM the admin an Approve/Deny button prompt.
    Returns True if approved, False if denied or timed out (60s).
    Called from main.py instead of raising a 403 for needs_confirmation.
    """
    if not _ADMIN_DISCORD_USER_ID:
        return False

    loop = asyncio.get_event_loop()
    future: asyncio.Future = loop.create_future()
    _pending_confirmations[request_id] = future

    try:
        admin_user = await bot.fetch_user(_ADMIN_DISCORD_USER_ID)
        dm = await admin_user.create_dm()

        factors_str = ", ".join(factors) if factors else "none"
        embed = discord.Embed(title="ShieldBot Approval Required", color=0xf0a500)
        embed.add_field(name="Agent", value=f"`{agent_name}`", inline=True)
        embed.add_field(name="Action", value=f"`{action_type}`", inline=True)
        embed.add_field(name="Risk Score", value=f"`{risk_score:.0f}/100`", inline=True)
        embed.add_field(name="Reason", value=reason, inline=False)
        embed.add_field(name="Factors", value=f"`{factors_str}`", inline=False)
        embed.set_footer(text=f"Request ID: {request_id} · Times out in 60s → auto-deny")

        view = _ApprovalView(request_id)
        await dm.send(embed=embed, view=view)

        try:
            return await asyncio.wait_for(future, timeout=60.0)
        except asyncio.TimeoutError:
            _pending_confirmations.pop(request_id, None)
            await dm.send(f"Request `{request_id}` timed out — auto-denied.")
            return False
    except Exception as e:
        log.warning(f"Discord approval request failed: {e}")
        _pending_confirmations.pop(request_id, None)
        return False


class _ApprovalView(discord.ui.View):
    def __init__(self, request_id: str):
        super().__init__(timeout=60)
        self.request_id = request_id

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.success)
    async def approve(self, interaction: discord.Interaction, button: discord.ui.Button):
        future = _pending_confirmations.pop(self.request_id, None)
        if future and not future.done():
            future.set_result(True)
        self.stop()
        await interaction.response.edit_message(content="Approved. The action will proceed.", embed=None, view=None)

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.danger)
    async def deny(self, interaction: discord.Interaction, button: discord.ui.Button):
        future = _pending_confirmations.pop(self.request_id, None)
        if future and not future.done():
            future.set_result(False)
        self.stop()
        await interaction.response.edit_message(content="Denied. The action has been blocked.", embed=None, view=None)


# ---------------------------------------------------------------------------
# Slash commands
# ---------------------------------------------------------------------------

@tree.command(name="register", description="Set up your Clawdbot permissions via a quick onboarding chat")
async def slash_register(interaction: discord.Interaction):
    if interaction.user.id in _sessions:
        await interaction.response.send_message(
            "You already have an onboarding in progress — check your DMs!", ephemeral=True
        )
        return
    await interaction.response.send_message("I've sent you a DM to get you set up!", ephemeral=True)
    await _start_onboarding(interaction.user)


@tree.command(name="permissions", description="Show what permissions your current agent has")
async def slash_permissions(interaction: discord.Interaction):
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                f"{SHIELDCLAW_URL}/shieldclaw/whoami",
                headers={"Authorization": f"Bearer {SHIELDCLAW_ADMIN_TOKEN}"},
            )
            data = resp.json()
            scopes = ", ".join(f"`{s}`" for s in data.get("scopes", []))
            identity = data.get("identity", {})
            await interaction.response.send_message(
                f"**Your identity:** `{identity.get('identity_type', '?')}`\n"
                f"**Agent:** `{identity.get('agent_name', '?')}`\n"
                f"**Scopes:** {scopes}",
                ephemeral=True,
            )
        except Exception as e:
            await interaction.response.send_message(f"Could not fetch permissions: {e}", ephemeral=True)


@tree.command(name="list-agents", description="List all registered ShieldClaw agents")
async def slash_list_agents(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                f"{SHIELDCLAW_URL}/shieldclaw/agents",
                headers={"Authorization": f"Bearer {SHIELDCLAW_ADMIN_TOKEN}"},
            )
            resp.raise_for_status()
            agents = resp.json().get("agents", [])
            if not agents:
                await interaction.followup.send("No agents registered yet.", ephemeral=True)
                return
            lines = []
            for a in agents:
                status = "revoked" if a.get("revoked") else "active"
                scopes = ", ".join(f"`{s}`" for s in a.get("scopes", []))
                lines.append(
                    f"**{a['agent_name']}** — {status}\n"
                    f"  ID: `{a['agent_id']}`\n"
                    f"  Scopes: {scopes}"
                )
            await interaction.followup.send("\n\n".join(lines), ephemeral=True)
        except Exception as e:
            await interaction.followup.send(f"Failed to list agents: `{e}`", ephemeral=True)


@tree.command(name="revoke", description="Revoke a ShieldClaw agent by ID")
@app_commands.describe(agent_id="The agent ID to revoke (get it from /list-agents)")
async def slash_revoke(interaction: discord.Interaction, agent_id: str):
    await interaction.response.defer(ephemeral=True)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(
                f"{SHIELDCLAW_URL}/shieldclaw/agents/{agent_id}/revoke",
                headers={"Authorization": f"Bearer {SHIELDCLAW_ADMIN_TOKEN}"},
            )
            resp.raise_for_status()
            await interaction.followup.send(
                f"Agent `{agent_id}` has been revoked. It can no longer authenticate.",
                ephemeral=True,
            )
        except httpx.HTTPStatusError as e:
            await interaction.followup.send(
                f"Failed ({e.response.status_code}): {e.response.text[:200]}", ephemeral=True
            )
        except Exception as e:
            await interaction.followup.send(f"Error: `{e}`", ephemeral=True)


@tree.command(name="rotate-secret", description="Rotate the client secret for an agent")
@app_commands.describe(agent_id="The agent ID to rotate (get it from /list-agents)")
async def slash_rotate_secret(interaction: discord.Interaction, agent_id: str):
    await interaction.response.defer(ephemeral=True)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(
                f"{SHIELDCLAW_URL}/shieldclaw/agents/{agent_id}/rotate-secret",
                headers={"Authorization": f"Bearer {SHIELDCLAW_ADMIN_TOKEN}"},
            )
            resp.raise_for_status()
            data = resp.json()
            await interaction.followup.send(
                f"**Secret rotated** for `{agent_id}`\n\n"
                f"**New Client Secret:** ||`{data['client_secret']}`||\n"
                f"*(click to reveal — save it now, it won't be shown again)*\n\n"
                f"The old secret is immediately invalid.",
                ephemeral=True,
            )
        except httpx.HTTPStatusError as e:
            await interaction.followup.send(
                f"Failed ({e.response.status_code}): {e.response.text[:200]}", ephemeral=True
            )
        except Exception as e:
            await interaction.followup.send(f"Error: `{e}`", ephemeral=True)


@tree.command(name="status", description="Check ShieldClaw gateway health")
async def slash_status(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            resp = await client.get(
                f"{SHIELDCLAW_URL}/shieldclaw/health",
                headers={"Authorization": f"Bearer {SHIELDCLAW_ADMIN_TOKEN}"},
            )
            data = resp.json() if resp.status_code == 200 else {}
            vault_status = data.get("vault", {})
            lines = [f"**ShieldClaw Gateway** — {'online' if resp.status_code == 200 else 'error'}"]
            for key, val in vault_status.items():
                icon = "set" if val == "set" else "MISSING"
                lines.append(f"  `{key}`: {icon}")
            await interaction.followup.send("\n".join(lines), ephemeral=True)
        except Exception:
            await interaction.followup.send(
                "**Gateway is unreachable.** Make sure ShieldClaw is running.", ephemeral=True
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not DISCORD_BOT_TOKEN:
        raise SystemExit("DISCORD_BOT_TOKEN is not set in .env")
    bot.run(DISCORD_BOT_TOKEN)
