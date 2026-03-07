#!/usr/bin/env python3
"""
ShieldClaw Discord Demo Bot — DM only.

Just DM the bot to start. /reset to restart anytime.
"""

import time
import httpx
import discord

DISCORD_TOKEN = "MTQ3OTY2OTEwMzM3MDQzNjY4OQ.GBBNwL.d8anHBXsSImR1rQyvtsXB1bHB0BbIy24mHmTD4"
SHIELDCLAW_URL = "http://localhost:8443"

AGENT_CLIENT_ID = "zBtyTbJqkIwy1cHW2Yw40dg6Z9e11t0d"
AGENT_CLIENT_SECRET = "cSd4bZERKgCSPr5NeBjBFJWivrM_8YgrrRYbwFvS1LFIw64YYWKm-qXv9sNnjU4B"
AGENT_ID = "agent_18f5b0d7858c"

AUTH0_DOMAIN = "codcodingcode.ca.auth0.com"
AUTH0_AUDIENCE = "https://shieldclaw-gateway"
ADMIN_TOKEN = "dev-bypass-token"

_sessions: dict = {}
_token_cache: dict = {}


async def get_agent_token() -> str:
    if _token_cache.get("token") and time.time() < _token_cache.get("expires", 0):
        return _token_cache["token"]
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": AGENT_CLIENT_ID,
                "client_secret": AGENT_CLIENT_SECRET,
                "audience": AUTH0_AUDIENCE,
            },
        )
        resp.raise_for_status()
        data = resp.json()
    _token_cache["token"] = data["access_token"]
    _token_cache["expires"] = time.time() + data.get("expires_in", 3600) - 60
    return _token_cache["token"]


intents = discord.Intents.default()
intents.message_content = True
intents.dm_messages = True
client = discord.Client(intents=intents)


async def start_onboarding(channel, user):
    _sessions[user.id] = {"step": "awaiting_use_case"}
    await channel.send(
        "Hey! I'm **ShieldBot**.\n\n"
        "I help you secure your AI agents using Auth0 — each agent gets its own identity "
        "and can only do exactly what you allow.\n\n"
        "**What do you plan to use this agent for?**\n\n"
        "Just tell me naturally:\n"
        "> *\"I want it to read my emails and send messages but nothing dangerous\"*\n"
        "> *\"It should browse the web and read files but never run commands on my computer\"*\n\n"
        "I'll lock it down based on what you say.\n\n"
        "*(Type `/reset` anytime to start over)*"
    )


async def handle_use_case(channel, user, use_case: str):
    _sessions[user.id]["step"] = "processing"
    await channel.send("Got it — figuring out the right permissions...")

    agent_name = f"agent-{user.name.lower().replace(' ', '-')[:20]}"

    try:
        async with httpx.AsyncClient(timeout=30) as http:
            resp = await http.post(
                f"{SHIELDCLAW_URL}/shieldclaw/agents",
                headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
                json={
                    "agent_name": agent_name,
                    "description": f"Created via ShieldBot DM for {user.name}",
                    "policy": use_case,
                },
            )

        if resp.status_code != 200:
            await channel.send(f"Something went wrong: {resp.status_code} — {resp.text[:300]}\n\nType `/reset` to try again.")
            _sessions.pop(user.id, None)
            return

        data = resp.json()
        scopes = data["scopes"]
        interp = data.get("policy_interpretation", {})

        await channel.send(
            f"Here's what I understood from:\n> *\"{use_case}\"*\n\n"
            f"**{interp.get('reasoning', 'Permissions derived from your description.')}**"
        )

        scope_explanations = {
            "gateway:read":       "read data",
            "gateway:message":    "send and receive messages",
            "gateway:tools":      "use tools like web search and file reading",
            "gateway:tools:exec": "run shell commands on your computer",
            "gateway:admin":      "full admin access",
            "gateway:canvas":     "access canvas and UI",
        }

        lines = []
        for s, label in scope_explanations.items():
            if s in scopes:
                lines.append(f"✅ `{s}` — {label}")
            else:
                lines.append(f"🚫 `{s}` — {label} *(blocked)*")

        await channel.send("**Your agent's permissions:**\n" + "\n".join(lines))

        embed = discord.Embed(
            title="Agent Created in Auth0",
            description="Your agent has its own identity, completely separate from yours.",
            color=0x00bfff
        )
        embed.add_field(name="Agent Name", value=data["agent_name"], inline=True)
        embed.add_field(name="Agent ID", value=f"`{data['agent_id']}`", inline=True)
        embed.add_field(name="Auth0 Client ID", value=f"`{data['client_id']}`", inline=False)
        embed.add_field(
            name="What this means",
            value=(
                "- This agent has its **own** Auth0 identity\n"
                "- It can **only** do what's listed above\n"
                "- Anything else is blocked at the identity layer\n"
                "- Type `/revoke` to kill it instantly"
            ),
            inline=False
        )
        embed.set_footer(text="Powered by Auth0 M2M — your credentials were never touched")
        await channel.send(embed=embed)
        await channel.send(
            f"**Client Secret:** `{data['client_secret']}`\n"
            "Save this — it cannot be retrieved again.\n\n"
            "Type `/whoami` to verify the identity or `/revoke` to kill it."
        )

        _sessions[user.id] = {"step": "done", "agent_id": data["agent_id"]}

    except Exception as e:
        await channel.send(f"Error: {e}\n\nMake sure ShieldClaw is running (`DEV_BYPASS=true python main.py`).")
        _sessions.pop(user.id, None)


@client.event
async def on_ready():
    print(f"ShieldBot online as {client.user} — DM only mode")


@client.event
async def on_message(message):
    if message.author == client.user:
        return
    if not isinstance(message.channel, discord.DMChannel):
        return

    text = message.content.strip()
    user = message.author
    channel = message.channel
    session = _sessions.get(user.id)

    # /reset — restart anytime
    if text.lower() == "/reset":
        await start_onboarding(channel, user)
        return

    # /whoami — show current agent identity
    if text.lower() == "/whoami":
        try:
            token = await get_agent_token()
            async with httpx.AsyncClient() as http:
                resp = await http.get(
                    f"{SHIELDCLAW_URL}/shieldclaw/whoami",
                    headers={"Authorization": f"Bearer {token}"},
                )
            data = resp.json()
            identity = data["identity"]
            scopes = data["scopes"]
            embed = discord.Embed(title="Agent Identity (Auth0)", color=0x00bfff)
            embed.add_field(name="Agent Name", value=identity["agent_name"], inline=True)
            embed.add_field(name="Identity Type", value=identity["identity_type"], inline=True)
            embed.add_field(name="Auth0 Client ID", value=f"`{identity['agent_client_id']}`", inline=False)
            embed.add_field(name="Scopes", value=" ".join(f"`{s}`" for s in scopes), inline=False)
            embed.set_footer(text="Token verified against Auth0 JWKS (RS256)")
            await channel.send(embed=embed)
        except Exception as e:
            await channel.send(f"Error: {e}")
        return

    # /revoke — kill the agent
    if text.lower() == "/revoke":
        try:
            async with httpx.AsyncClient() as http:
                resp = await http.post(
                    f"{SHIELDCLAW_URL}/shieldclaw/agents/{AGENT_ID}/revoke",
                    headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
                )
            if resp.status_code == 200:
                embed = discord.Embed(title="Agent Revoked", color=0xff6600)
                embed.add_field(name="Effect", value="Auth0 M2M app deleted. Token permanently invalid.", inline=False)
                embed.set_footer(text="Type /whoami to confirm it's dead. Type /reset to create a new one.")
                await channel.send(embed=embed)
            else:
                await channel.send(f"Error: {resp.status_code} — {resp.text}")
        except Exception as e:
            await channel.send(f"Error: {e}")
        return

    # First time DMing — auto start
    if not session:
        await start_onboarding(channel, user)
        return

    # Waiting for use case
    if session["step"] == "awaiting_use_case":
        await handle_use_case(channel, user, text)
        return

    # Already set up
    if session["step"] == "done":
        await channel.send("Your agent is already set up.\n\n`/whoami` — see the identity\n`/revoke` — kill it\n`/reset` — start over")
        return


client.run(DISCORD_TOKEN)
