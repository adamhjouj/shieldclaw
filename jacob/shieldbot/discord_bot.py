#!/usr/bin/env python3
"""Shieldbot Discord bot — OpenClaw-style chat with local tool execution.

Talk to the bot by @mentioning it in a channel or DMing it directly.
It can list files, read files, and evaluate security actions.
All routed through Backboard.io with persistent memory.
"""

from __future__ import annotations

import sys
import os
import json
import re
import subprocess

if __name__ == "__main__":
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import discord

from jacob.shieldbot import backboard_client

DISCORD_TOKEN = "MTQzNjQ2MjEwMTAwMTUzOTYxNQ.GXB94T.zjvIhgwLXzUCyP2SObfuEvTSpARyu1rN8ZewJk"

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

_channel_threads: dict[int, str] = {}

MENTION_PATTERN = re.compile(r"<@!?\d+>")


# ── Local tool execution ──

def execute_tool(name: str, arguments: dict) -> str:
    """Execute a tool locally and return the result as a string."""
    if name == "list_files":
        return _tool_list_files(arguments.get("path", "."))
    elif name == "read_file":
        return _tool_read_file(arguments.get("path", ""))
    elif name == "send_email":
        return _tool_send_email(
            arguments.get("to", ""),
            arguments.get("subject", ""),
            arguments.get("body", ""),
            arguments.get("attachment_path"),
        )
    return f"Unknown tool: {name}"


def _tool_list_files(path: str) -> str:
    try:
        expanded = os.path.expanduser(path)
        if not os.path.isdir(expanded):
            return f"Not a directory: {path}"
        entries = os.listdir(expanded)
        dirs = sorted([e + "/" for e in entries if os.path.isdir(os.path.join(expanded, e))])
        files = sorted([e for e in entries if os.path.isfile(os.path.join(expanded, e))])
        result = dirs + files
        if not result:
            return f"(empty directory: {path})"
        if len(result) > 50:
            return "\n".join(result[:50]) + f"\n... and {len(result) - 50} more"
        return "\n".join(result)
    except PermissionError:
        return f"Permission denied: {path}"
    except Exception as e:
        return f"Error listing {path}: {e}"


def _tool_read_file(path: str) -> str:
    try:
        expanded = os.path.expanduser(path)
        if not os.path.isfile(expanded):
            return f"Not a file: {path}"
        size = os.path.getsize(expanded)
        if size > 50000:
            return f"File too large to read ({size} bytes). Try a smaller file."
        with open(expanded, "r", errors="replace") as f:
            content = f.read()
        if len(content) > 3000:
            return content[:3000] + f"\n... (truncated, {size} bytes total)"
        return content
    except PermissionError:
        return f"Permission denied: {path}"
    except Exception as e:
        return f"Error reading {path}: {e}"


def _tool_send_email(to: str, subject: str, body: str, attachment_path: str | None = None) -> str:
    try:
        if not to:
            return "Error: no recipient email provided"

        safe_subject = subject.replace('"', '\\"').replace("'", "\\'")
        safe_body = body.replace('"', '\\"').replace("'", "\\'").replace("\n", "\\n")

        lines = [
            'tell application "Mail"',
            f'  set newMsg to make new outgoing message with properties {{subject:"{safe_subject}", content:"{safe_body}"}}',
            '  tell newMsg',
            '    set visible to true',
            f'    make new to recipient at end of to recipients with properties {{address:"{to}"}}',
        ]

        if attachment_path:
            expanded = os.path.expanduser(attachment_path)
            if os.path.isdir(expanded):
                return f"Cannot attach a folder directly: {attachment_path}. Specify a file inside it."
            if not os.path.isfile(expanded):
                return f"Attachment not found: {attachment_path}"
            abs_path = os.path.abspath(expanded)
            lines.append(f'    tell content')
            lines.append(f'      make new attachment with properties {{file name:POSIX file "{abs_path}"}} at after the last paragraph')
            lines.append(f'    end tell')

        lines.extend([
            '    send',
            '  end tell',
            'end tell',
        ])

        script = "\n".join(lines)
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return f"Email sent successfully to {to} with subject '{subject}'" + (f" (attached: {attachment_path})" if attachment_path else "")
        stderr = result.stderr.strip()
        if "not allowed" in stderr.lower() or "permission" in stderr.lower():
            return f"Mail.app needs permission. Open System Settings > Privacy > Automation and allow Terminal to control Mail."
        return f"Mail.app returned: {stderr or 'unknown error'}"
    except subprocess.TimeoutExpired:
        return f"Email send timed out — check Mail.app"
    except Exception as e:
        return f"Error sending email: {e}"


# ── Backboard thread management ──

def _get_or_create_thread(channel_id: int) -> str:
    if channel_id in _channel_threads:
        return _channel_threads[channel_id]
    thread = backboard_client.create_thread()
    thread_id = thread["thread_id"]
    _channel_threads[channel_id] = thread_id
    return thread_id


def _send_and_handle_tools(thread_id: str, content: str) -> str:
    """Send a message to Backboard, handle any tool calls, return final text."""
    resp = backboard_client.add_message(
        thread_id, content,
        memory="Auto", send_to_llm="true",
    )

    # Check if the LLM wants to call tools
    tool_calls = resp.get("tool_calls")
    run_id = resp.get("run_id")

    if not tool_calls or not run_id:
        return resp.get("content", "")

    # Execute each tool call locally
    tool_outputs = []
    for tc in tool_calls:
        func = tc.get("function", {})
        name = func.get("name", "")
        try:
            args = json.loads(func.get("arguments", "{}"))
        except json.JSONDecodeError:
            args = {}

        print(f"[shieldbot] Tool call: {name}({args})")
        result = execute_tool(name, args)
        tool_outputs.append({
            "tool_call_id": tc["id"],
            "output": result,
        })

    # Submit tool outputs back to Backboard
    final = backboard_client.submit_tool_outputs(thread_id, run_id, tool_outputs)

    # The LLM might request more tools (recursive)
    more_tools = final.get("tool_calls")
    more_run_id = final.get("run_id")
    if more_tools and more_run_id:
        more_outputs = []
        for tc in more_tools:
            func = tc.get("function", {})
            name = func.get("name", "")
            try:
                args = json.loads(func.get("arguments", "{}"))
            except json.JSONDecodeError:
                args = {}
            print(f"[shieldbot] Tool call (round 2): {name}({args})")
            result = execute_tool(name, args)
            more_outputs.append({"tool_call_id": tc["id"], "output": result})
        final = backboard_client.submit_tool_outputs(thread_id, more_run_id, more_outputs)

    return final.get("content", "")


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
    print(f"[shieldbot] Backboard.io: CONNECTED → {backboard_client.BASE_URL}")
    print(f"[shieldbot] Tools: list_files, read_file")
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
            thread_id = _get_or_create_thread(message.channel.id)
            reply = _send_and_handle_tools(thread_id, content)

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
