# ShieldClaw — How OpenClaw Works & How to Add Security On Top

## How OpenClaw Actually Works

OpenClaw is an AI coding agent that runs as a **gateway server** on your machine. It connects to LLMs (Claude, GPT, etc.) and lets you interact with them through channels like Discord, Slack, Telegram, iMessage, or a web UI. The agent can read files, write code, run shell commands, and manage projects — basically a self-hosted AI dev assistant.

### The Core Loop

```
You (via Discord/Slack/CLI/Web)
  --> Gateway Server (Node.js, Express + WebSocket)
    --> Auth check (token/password/none)
    --> Route to correct channel handler
    --> Build agent prompt (SOUL.md + skills + context)
    --> Send to LLM (Claude/GPT/etc.)
    --> LLM responds, possibly calling tools
    --> Tools execute (file read/write, shell, browser, etc.)
    --> Response sent back to you through your channel
```

### Key Architecture Pieces

**Gateway (`src/gateway/`)** — The brain. An Express + WebSocket server that handles all incoming requests. Entry point is `server.impl.ts` (~6000 LOC). It manages auth, routing, sessions, plugin loading, and agent execution.

**Channels** — How users talk to the agent. Each channel (Discord, Slack, Telegram, etc.) is an extension in `extensions/`. They translate platform-specific messages into a common format the gateway understands. There are 42+ channel integrations.

**Skills (`skills/`)** — NOT executable code. Each skill is a `SKILL.md` file (YAML frontmatter + markdown) that teaches the agent how to use a tool. For example, `skills/github/SKILL.md` describes how to use the `gh` CLI. The agent reads these instructions and follows them. There are 54 bundled skills.

Example skill structure:
```yaml
---
name: github
description: "GitHub operations via gh CLI"
metadata:
  openclaw:
    emoji: "🐙"
    requires: { bins: ["gh"] }
    install:
      - { id: "brew", kind: "brew", formula: "gh" }
---
# GitHub Skill
Use `gh pr list` to list pull requests...
```

**SOUL.md** — The agent's personality and rules. This is the system prompt that tells the agent how to behave. It's loaded at startup via the `boot-md` hook (`src/hooks/bundled/boot-md/handler.ts`) and injected into every LLM call. This is where you'd add security rules like "never run rm -rf" or "always ask before executing shell commands."

**Plugins (`src/plugins/`)** — The extension system. Plugins run in-process with the gateway and can hook into lifecycle events:
- `before_agent_start` — before the agent begins processing
- `before_tool_call` — before any tool executes
- `after_tool_call` — after a tool returns
- `before_prompt_build` — before the system prompt is assembled
- `llm_output` — when the LLM responds
- `message_sending` — before a message is sent back to the user

**Security (`src/security/`)** — Existing security is basic but extensive:
- `audit.ts` (~6000 LOC) — policy enforcement for tools, channels, content
- Tool profiles: `messaging` (safe), `power` (more access), `hacker` (everything), `custom`
- Per-channel action groups (can the bot react? pin? moderate? manage roles?)
- DM policies, external content restrictions, secrets management

### Current Auth System

Lives in `src/gateway/auth.ts`. Four modes:
- `none` — no auth, anyone can connect
- `token` — bearer token in header
- `password` — password-based
- `trusted-proxy` — trust a reverse proxy's headers

Only two roles exist: `operator` (full access) and `node` (paired device). There's no concept of multiple users, organizations, or granular permissions. It's designed for **one person running it on their own machine**.

### Config

Everything is configured in `openclaw.json` (JSON5 format). Validated with Zod schemas in `src/config/`. State lives in `~/.openclaw/`.

---

## How You'd Add Security (The ShieldClaw Layer)

### The Two Places That Matter

1. **`skills/`** — Drop in new SKILL.md files that teach the agent about security. These are just markdown files describing capabilities.

2. **`SOUL.md`** — Add rules to the agent's instruction file. Anything you write here becomes part of every LLM call. Example additions:
   - "You are operating under ShieldClaw security policy."
   - "Before executing any shell command, verify the user has permission."
   - "Never include API keys, passwords, or PII in responses."
   - "If a request seems destructive, ask for explicit confirmation."

### Adding Auth0 (Multi-User Authentication)

OpenClaw's auth is single-user. To make it multi-user with Auth0:

**What you'd change:**

1. **`src/config/types.gateway.ts`** — Add `"auth0"` to the auth mode union. Add config fields for `domain`, `clientId`, `audience`, `rolesClaim`.

2. **`src/gateway/auth.ts`** — Add a new branch in `authorizeGatewayConnect()` for `auth.mode === "auth0"`. This function already switches on auth mode, so you'd add one more case that validates a JWT instead of a static token.

3. **New file: `src/gateway/auth-auth0.ts`** — JWT verification using the `jose` library. Validates tokens against Auth0's JWKS endpoint, extracts user identity (email, roles, org).

4. **`src/gateway/server/http-auth.ts`** — Accept `Authorization: Bearer <jwt>` and route to Auth0 verification.

5. **`src/gateway/server/ws-connection/auth-context.ts`** — Same for WebSocket connections.

6. **`src/gateway/role-policy.ts`** — Extend from 2 roles (`operator`, `node`) to meaningful roles: `admin`, `developer`, `viewer`, `auditor`. Map Auth0 role claims to these internal roles.

**The flow becomes:**
```
User connects with Auth0 JWT
  --> Gateway validates JWT against Auth0 JWKS
  --> Extracts: who they are, what role they have, what org they're in
  --> Maps Auth0 roles to internal roles
  --> Passes identity through to all handlers and hooks
```

### Adding Backboard (Policy Enforcement / Guardrails)

Backboard is the layer that decides what the agent can and can't do, based on who's asking.

**Cleanest approach: build it as a plugin.** OpenClaw's plugin system already has hooks at every stage of the request lifecycle. You don't need to gut the core — just register hooks.

**What you'd build:**

A plugin at `extensions/shieldclaw-backboard/` that registers these hooks:

| Hook | What It Does |
|------|-------------|
| `before_agent_start` | **Input gate.** Can this user start a session? What tool profile should they get? An `admin` gets `power` tools, a `viewer` gets read-only. |
| `before_tool_call` | **Tool gate.** Is this specific tool allowed for this user? A `developer` can use `file_read` and `file_write` but not `shell_exec`. Checks tool arguments too (no path traversal, no accessing `/etc/shadow`). |
| `before_prompt_build` | **Prompt injection.** Adds security rules to the system prompt dynamically based on the user's role: "Current user is a developer. Do not run destructive commands." |
| `llm_output` | **Output scanner.** Scans what the LLM says for PII, leaked credentials, API keys, secrets. Redacts or blocks. |
| `message_sending` | **Final gate.** Last chance to filter before the response reaches the user. |

**Policy definitions** would live as YAML files in a `policies/` directory:

```yaml
id: default-policy
name: Default Security Policy
rules:
  - effect: deny
    actions: ["shell_exec", "file_delete"]
    conditions:
      - field: user.role
        operator: not_in
        values: ["admin"]

  - effect: redact
    actions: ["*"]
    conditions:
      - field: output
        operator: matches
        values: ["password", "secret", "api_key", "token"]
```

**Config in `openclaw.json`:**
```json
{
  "gateway": {
    "backboard": {
      "enabled": true,
      "policyDir": "./policies",
      "defaultToolProfile": "messaging",
      "contentFilter": {
        "piiDetection": true,
        "secretRedaction": true
      },
      "rolePolicies": {
        "admin": { "toolProfile": "power" },
        "developer": { "toolProfile": "messaging", "allowedTools": ["file_read", "file_write"] },
        "viewer": { "allowedTools": ["file_read"] }
      }
    }
  }
}
```

### Security Skills to Add

Drop these in the `skills/` folder as SKILL.md files:

- **`skills/security-audit/SKILL.md`** — Teaches the agent to run security checks scoped to the user's permissions
- **`skills/policy-check/SKILL.md`** — Teaches the agent to tell users what they can and can't do
- **`skills/incident-report/SKILL.md`** — Teaches the agent to generate reports when something gets blocked

### The Full Picture After ShieldClaw

```
User sends message (via Discord/Slack/CLI)
  |
  v
[AUTH0] Validate JWT, extract identity + roles
  |
  v
[GATEWAY] Check role has access to this method
  |
  v
[BACKBOARD] Input policy — can this user do this?
  |           Downgrade tool profile if needed
  |           Scan input for prompt injection
  |
  v
[AGENT] LLM processes request with security-augmented prompt
  |      Tools execute within permitted boundaries
  |
  v
[BACKBOARD] Output filter — scan for PII, secrets, violations
  |          Redact or block as needed
  |
  v
User receives filtered response
```

---

## Key Risks to Know About

**Multi-tenant isolation doesn't exist.** OpenClaw assumes one user per machine. Sessions, agent state, and memory are NOT scoped per-user. If you add Auth0 for multi-user, you also need to add session isolation — otherwise User A might see User B's agent history. This is the hardest part.

**Fork maintenance.** The more core files you modify, the harder it is to pull upstream updates. The plugin approach (Backboard as a plugin, not core changes) minimizes this pain.

**Identity threading.** The Auth0 identity needs to flow from the initial auth check all the way through to every plugin hook. The existing plugin context types (`PluginHookAgentContext`, `OpenClawPluginToolContext` in `src/plugins/types.ts`) don't include user identity — you'd need to extend them.

**Performance.** Running policy checks on every tool call adds latency. Cache resolved policies per-session since they don't change mid-conversation.

---

## Summary: What to Actually Do

1. **Clone the main OpenClaw repo** from `github.com/openclaw/openclaw`
2. **Run it in dev mode** — `pnpm install`, then run from source so your changes take effect immediately
3. **Start with SOUL.md** — add security rules to the agent's instructions (zero-code, immediate effect)
4. **Add security skills** — drop SKILL.md files in `skills/` to teach the agent security behaviors
5. **Build Auth0 integration** — extend `src/gateway/auth.ts` with a new `"auth0"` mode
6. **Build Backboard as a plugin** — register hooks in `extensions/shieldclaw-backboard/` for policy enforcement
7. **Add policies** — define role-based policies as YAML in a `policies/` directory
8. **Handle multi-tenancy** — scope sessions and state per-user (the hard part)
