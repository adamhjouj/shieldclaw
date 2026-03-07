#!/usr/bin/env python3
"""
Polls `openclaw pairing list discord --json` every few seconds.
When a new pairing request appears, DMs the admin on Discord with Approve/Deny buttons.
Run this alongside openclaw start.
"""

import asyncio
import json
import os
import subprocess
import sys

import discord
from dotenv import load_dotenv

load_dotenv()

DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
_admin_id_raw = os.environ.get("DISCORD_ADMIN_USER_ID", "").strip()
DISCORD_ADMIN_USER_ID: int | None = int(_admin_id_raw) if _admin_id_raw.isdigit() else None
POLL_INTERVAL = 4  # seconds

intents = discord.Intents.default()
client = discord.Client(intents=intents)

# Track codes we've already sent a button for so we don't spam
_seen_codes: set[str] = set()


def _list_pending() -> list[dict]:
    """Run openclaw pairing list discord --json and return the requests."""
    try:
        result = subprocess.run(
            ["openclaw", "pairing", "list", "discord", "--json"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout)
        return data.get("requests", [])
    except Exception as e:
        print(f"[pairing-watcher] list error: {e}")
        return []


class _PairingView(discord.ui.View):
    def __init__(self, code: str, requester_id: str):
        super().__init__(timeout=600)  # 10 min
        self.code = code
        self.requester_id = requester_id

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
                await interaction.edit_original_response(
                    content=f"Approved `{self.code}` (user `{self.requester_id}`). They've been notified."
                )
                try:
                    user = await client.fetch_user(int(self.requester_id))
                    await user.send("You've been approved! Go ahead and send me a message.")
                except Exception:
                    pass
            else:
                err = (result.stderr or result.stdout or "unknown error").strip()
                await interaction.edit_original_response(
                    content=f"Failed to approve `{self.code}`:\n```\n{err}\n```"
                )
        except Exception as e:
            await interaction.edit_original_response(content=f"Error: `{e}`")

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.danger)
    async def deny(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(
            content=f"Denied `{self.code}` (user `{self.requester_id}`).", view=None
        )
        try:
            user = await client.fetch_user(int(self.requester_id))
            await user.send("Sorry, your access request was denied.")
        except Exception:
            pass


async def _poll_loop():
    await client.wait_until_ready()
    if not DISCORD_ADMIN_USER_ID:
        print("[pairing-watcher] ERROR: DISCORD_ADMIN_USER_ID not set in .env — can't send DMs")
        return

    print(f"[pairing-watcher] Watching for pairing requests (polling every {POLL_INTERVAL}s)...")
    while not client.is_closed():
        requests = _list_pending()
        for req in requests:
            code = req.get("code", "")
            requester_id = req.get("id", "unknown")
            if not code or code in _seen_codes:
                continue
            _seen_codes.add(code)
            print(f"[pairing-watcher] New pairing request: code={code} from={requester_id}")
            try:
                admin = await client.fetch_user(DISCORD_ADMIN_USER_ID)
                meta = req.get("meta", {})
                name = meta.get("name") or meta.get("tag") or requester_id
                view = _PairingView(code=code, requester_id=requester_id)
                await admin.send(
                    f"**Pairing request** from **{name}** (`{requester_id}`)\n"
                    f"Code: `{code}`\n\nApprove to let them in.",
                    view=view,
                )
                # Send the user something friendlier
                try:
                    user = await client.fetch_user(int(requester_id))
                    await user.send(
                        "Access not set up yet — I've sent a request to the bot owner to approve you! Hang tight."
                    )
                except Exception:
                    pass
            except Exception as e:
                print(f"[pairing-watcher] Failed to DM admin: {e}")

        await asyncio.sleep(POLL_INTERVAL)


@client.event
async def on_ready():
    print(f"[pairing-watcher] Logged in as {client.user}")
    client.loop.create_task(_poll_loop())


if __name__ == "__main__":
    if not DISCORD_BOT_TOKEN:
        sys.exit("DISCORD_BOT_TOKEN not set in .env")
    client.run(DISCORD_BOT_TOKEN)
