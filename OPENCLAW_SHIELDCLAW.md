# OpenClaw + ShieldClaw: How They Fit Together

## What Each Thing Is

**OpenClaw** is the AI agent runtime. It runs on your machine, connects to Claude, and talks to you via Discord. It can read files, run shell commands, browse the web, and use plugins. Think of it as the engine.

**ShieldClaw** (`main.py`) is a security proxy that sits in front of OpenClaw. All requests go through ShieldClaw first. ShieldClaw checks Auth0 JWTs, enforces scopes, runs ShieldBot risk evaluation, and only forwards approved requests to OpenClaw. Think of it as the gatekeeper.

**The Discord bot** (`discord_onboarding.py` + `jacob/shieldbot/discord_bot.py`) is how you talk to the whole system. The chat bot sends your messages through ShieldClaw → OpenClaw → Claude.

---

## How They Connect (Right Now, Live)

```
You (Discord)
  |
  v
OpenClaw Discord channel (port 18789, internal)
  |
  | OpenClaw forwards agent tool calls + LLM requests
  v
ShieldClaw gateway (port 8443)
  --> Verifies token: "shieldclaw-local-token" (from openclaw.json)
  --> Runs ShieldBot evaluation
  --> If approved, proxies to OpenClaw at 127.0.0.1:18789
  |
  v
OpenClaw processes the request with Claude
```

**Key config values (from ~/.openclaw/openclaw.json):**

| Setting | Value |
|---|---|
| OpenClaw gateway port | `18789` |
| OpenClaw auth mode | `token` |
| OpenClaw auth token | `shieldclaw-local-token` |
| ShieldClaw expects OpenClaw at | `http://127.0.0.1:18789` (OPENCLAW_UPSTREAM in .env) |
| ShieldClaw listens on | `8443` |
| Exec ask prompts | `off` (shell commands run without asking) |
| Discord token | same token in both openclaw.json and .env |

---

## The exec Allowlist Issue

The logs show `exec denied: allowlist miss`. This is OpenClaw's exec tool blocking commands that aren't on its allowlist.

OpenClaw's exec tool has two enforcement layers:
1. **`tools.exec.ask`** — set to `"off"` in your openclaw.json, so it won't ask for approval
2. **`gateway.nodes.denyCommands`** — a list of explicitly denied commands (camera, screen record, etc.)

The `allowlist miss` error means OpenClaw is running in a mode where only pre-approved commands are allowed. Check `~/.openclaw/exec-approvals.json` — that file controls which commands are permanently approved.

---

## The Two Discord Bots

You have two separate Discord bot files:

### 1. `jacob/shieldbot/discord_bot.py`
- The **chat bot** — handles `@mentions` and DMs
- Sends messages to `ShieldClaw /v1/chat/completions` → proxied to OpenClaw
- Uses `SHIELDCLAW_TOKEN=dev-bypass-token` to authenticate
- This is the bot users actually talk to

### 2. `discord_onboarding.py`
- The **admin/management bot** — handles slash commands
- `/register` — onboards new users (DM flow with Claude)
- `/list-agents`, `/revoke`, `/rotate-secret`, `/status` — agent management
- Approval buttons for ShieldBot `needs_confirmation` decisions
- Both bots share the same `DISCORD_BOT_TOKEN`

Currently they're two separate processes. They can be merged into one bot later.

---

## ShieldBot Evaluation Flow

Every request an agent makes goes through this pipeline in `main.py`:

```
Request arrives at ShieldClaw (port 8443)
  |
  1. JWT verification (Auth0 or dev-bypass-token)
  2. Revocation check (is this agent banned?)
  3. Scope check (does the token have permission for this route?)
  4. FGA policy check (fga.py — fine-grained access control)
  5. ShieldBot evaluation (evaluator.py via Backboard/Anthropic)
     |
     +--> approved  → forward to OpenClaw
     +--> blocked   → 403, done
     +--> needs_confirmation → DM you on Discord with Approve/Deny buttons
                               60s timeout → auto-deny if no response
  |
  6. Proxy request to OpenClaw at 127.0.0.1:18789
  7. Redact sensitive data from response (data_policy.py)
  8. Return response to caller
```

---

## Auth Tokens: What Goes Where

| Token | Where it lives | What it's for |
|---|---|---|
| `dev-bypass-token` | `.env` SHIELDCLAW_ADMIN_TOKEN | Skips Auth0 JWT verification in ShieldClaw (dev only) |
| `shieldclaw-local-token` | `~/.openclaw/openclaw.json` gateway.auth.token | OpenClaw only accepts requests with this token |
| `DISCORD_BOT_TOKEN` | `.env` | Discord bot identity |
| `ANTHROPIC_API_KEY` | `.env` | Direct Claude calls (ShieldBot evaluation) |
| `BACKBOARD_API_KEY` | `.env` + `~/.openclaw/.env` | Backboard.io for ShieldBot LLM routing + memory |
| Auth0 credentials | `.env` AUTH0_* | Production JWT verification (bypassed when DEV_BYPASS=true) |

---

## OpenClaw Config That Matters for ShieldClaw

From `~/.openclaw/openclaw.json`:

```json
"gateway": {
  "port": 18789,           // ShieldClaw proxies here (OPENCLAW_UPSTREAM)
  "mode": "local",
  "bind": "loopback",      // Only accepts connections from localhost
  "auth": {
    "mode": "token",
    "token": "shieldclaw-local-token"  // Must match what ShieldClaw sends
  }
}

"tools": {
  "exec": {
    "host": "gateway",
    "ask": "off"           // Shell commands don't ask for approval
  }
}

"channels": {
  "discord": {
    "enabled": true,
    "token": "...",
    "groupPolicy": "allowlist",  // Only responds in allowlisted servers
    "streaming": "off"
  }
}
```

**Important:** `bind: loopback` means OpenClaw only accepts connections from `127.0.0.1`. ShieldClaw must run on the same machine. This is intentional — ShieldClaw is the only thing that should be talking to OpenClaw directly.

---

## Plugins Active in OpenClaw

| Plugin | What it does |
|---|---|
| `crawl4ai` | Web scraping/crawling (hosted on Railway) |
| `backboard-memory` | Persistent memory across conversations via Backboard.io |
| `discord` | Discord channel integration |

The `backboard-memory` plugin uses a different API key than ShieldBot (`~/.openclaw/.env` BACKBOARD_API_KEY vs `.env` ANTHROPIC_API_KEY). Both point to Backboard.io but as different assistants.

---

## Where the exec Errors Come From

The log lines:
```
[tools] exec failed: exec denied: allowlist miss
[tools] read failed: EISDIR: illegal operation on a directory, read
```

- **`exec denied: allowlist miss`** — OpenClaw is being asked to run a shell command that isn't in `~/.openclaw/exec-approvals.json`. Since `ask: off`, it fails silently instead of prompting.
- **`read failed: EISDIR`** — The `read_file` tool was passed a directory path instead of a file path. OpenClaw tried to open it as a file and got `EISDIR`.

Neither of these is a ShieldClaw bug. They originate inside OpenClaw's tool execution layer.

---

## Starting Everything

To run the full stack:

```
# Terminal 1 — OpenClaw (the agent runtime + Discord channel)
# See "Starting OpenClaw" section below — DO NOT use `openclaw gateway stop/restart`

# Terminal 2 — ShieldClaw (the security proxy)
python main.py

# Terminal 3 — Discord management bot (slash commands + approval buttons)
python discord_onboarding.py
```

Or combine Terminal 2 + 3 into one process (future work — they share the same event loop but need to be merged).

---

## ⚠️ Starting OpenClaw (IMPORTANT — Read This First)

**This repo contains a custom modified version of OpenClaw** in the `openclaw/` directory. It is NOT the same as the system-installed `openclaw` binary at `/opt/homebrew/bin/openclaw`.

**NEVER use these commands** — they operate on the wrong (system) OpenClaw:
- `openclaw gateway stop`
- `openclaw gateway restart`
- `openclaw gateway run`
- Any other `openclaw` CLI command

**To start the custom OpenClaw gateway**, the user must start it themselves via whatever method they use (e.g. the OpenClaw macOS app, or their own script). Do NOT attempt to start/stop/restart it via the CLI or via `node openclaw.mjs` or `kill` commands.

**The exec-approvals config** lives at `~/.openclaw/exec-approvals.json`. The correct value for `defaults.security` is `"full"` (not `"none"` — that's invalid and falls back to `"deny"`). After editing this file, the user must restart OpenClaw themselves for it to take effect.
