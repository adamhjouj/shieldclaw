# ShieldClaw FGA (Fine-Grained Authorization) System — Complete Build Specification

## Purpose of This Document

This document is a complete, detailed specification of ShieldClaw's Fine-Grained Authorization (FGA) system. It describes exactly how the system works, every blocked command/keyword, every allowed operation, the authorization model, data redaction, and all integration points. Use this to rebuild the FGA system from scratch or to understand every security decision it makes.

---

## High-Level Architecture

ShieldClaw uses a **two-layer FGA system** to control what AI agents can do:

1. **Layer 1: Local YAML Policy Engine** — Fast, offline, deterministic. Evaluates deny/allow rules against commands, paths, routes, HTTP methods, and action types. Defined in `fga_policy.yaml`, executed by `fga.py`.

2. **Layer 2: Auth0 OpenFGA (Relationship-Based)** — Remote, flexible, fine-grained. Checks whether a specific agent has a specific relationship (e.g., `owner`, `editor`, `can_read`) to a specific resource (e.g., a file, email, thread). Defined in `fga-model.fga`, executed by `fga_client.py`.

Both layers work together in a strict evaluation order:
1. YAML deny rules — checked first. Any match = **immediate hard block** (no FGA call needed).
2. YAML allow rules — checked second. First match = permit.
3. Auth0 FGA relationship check — if configured, checks relationship tuples for resource-level access.
4. No match = **default deny**. Nothing gets through without an explicit allow rule.

### Critical Requirement: Rejection Messages

**Every single rejection response MUST state that the block is due to Auth0's FGA restrictions.** The rejection reason is prefixed with `[FGA]` and the reason text attributes the block to Auth0 FGA policy, even for YAML-layer blocks. Examples:
- `"[FGA] Agents cannot change file permissions — blocked by Auth0 FGA"`
- `"[FGA] Recursive force delete is too destructive for agents"`
- `"[FGA] No allow rule matched for action 'post:tools'. Default-deny policy."`

The HTTP response is always **403 Forbidden** with the `detail` field containing the `[FGA]` prefixed reason.

---

## Layer 1: YAML Policy Engine (`fga.py`)

### Core Classes

#### `FGAResult` (dataclass)
```python
@dataclass
class FGAResult:
    allowed: bool           # True = permit, False = block
    reason: str             # Human-readable reason (shown in 403 response)
    matched_rule: str       # The rule dict that matched (for audit logging)
    rule_type: str          # "allow" | "deny" | "default-deny" | "fga-allow" | "fga-deny"
```

#### `FGAPolicy`
Loads a YAML policy file and evaluates requests against it. Supports these matchers (all optional, multiple matchers AND together):

| Matcher | Description | Match Logic |
|---------|-------------|-------------|
| `path_prefix` | Filesystem or URL path | Checks if the request's `path`, `file`, or `directory` field starts with this prefix. `~` is expanded to home directory. |
| `command` | Substring match | Checks if the substring appears (case-insensitive) in: `action_type`, `body.command`, `body.cmd`, or `body.action` |
| `method` | HTTP method | Exact match against `GET`, `POST`, `PUT`, `DELETE`, `PATCH` |
| `route_prefix` | API route prefix | Checks if the request path starts with this prefix |
| `action_type` | Regex match | Full regex match against the `action_type` string |
| `reason` | Rejection message | Human-readable explanation shown in the 403 response. Must attribute block to Auth0 FGA. |

**When multiple matchers are present in a single rule, they ALL must match (AND logic).**

#### `FGAEngine`
Singleton that manages policy caching:
- Loads global default policy from `fga_policy.yaml`
- Supports per-agent overrides via `fga_policy_{agent_id}.yaml`
- Falls back to global if no per-agent file exists
- Has a `reload()` method to force re-read from disk

### Public Functions

```python
def check_fga(agent_id: str, action_type: str, payload: dict) -> FGAResult
    # Synchronous, YAML-only check

async def check_fga_full(agent_id: str, action_type: str, payload: dict, user_sub: str = None) -> FGAResult
    # Full async check: YAML first, then Auth0 FGA relationship check
```

---

## Complete Deny Rules (Hard Blocks)

These are ALL the commands, paths, routes, and keywords that are blocked. Every single one of these returns a 403 with a reason stating the block is due to Auth0 FGA restrictions.

### 1. Credential & Secret File Access

| Blocked Path Prefix | Rejection Reason |
|---------------------|-----------------|
| `~/.ssh` | `"SSH keys are off-limits to agents"` |
| `~/.aws` | `"AWS credentials are off-limits to agents"` |
| `~/.gnupg` | `"GPG keys are off-limits to agents"` |
| `~/.config/gcloud` | `"GCloud credentials are off-limits to agents"` |
| `.env` | `"Local .env files may contain secrets — agents cannot read them"` |
| `~/.env` | `"Home .env file is off-limits to agents"` |

### 2. Destructive Git Operations

| Blocked Command (substring match) | Rejection Reason |
|-----------------------------------|-----------------|
| `git push --force` | `"Force push is too destructive for autonomous agent use"` |
| `git push -f` | `"Force push is too destructive for autonomous agent use"` |
| `git reset --hard` | `"Hard reset destroys uncommitted work — not permitted for agents"` |
| `git clean -f` | `"Force clean destroys untracked files — not permitted for agents"` |
| `git rebase -i` | `"Interactive rebase requires human judgment"` |

### 3. Dangerous Shell Commands

| Blocked Command (substring match) | Rejection Reason |
|-----------------------------------|-----------------|
| `rm -rf` | `"Recursive force delete is too destructive for agents"` |
| `rm -r` | `"Recursive delete requires explicit human approval"` |
| `sudo` | `"Privilege escalation is not permitted for agents"` |
| `chmod` | `"Agents cannot change file permissions — blocked by Auth0 FGA"` |
| `chown` | `"Agents cannot change file ownership — blocked by Auth0 FGA"` |
| `chgrp` | `"Agents cannot change file group ownership — blocked by Auth0 FGA"` |
| `setfacl` | `"Agents cannot modify file ACLs — blocked by Auth0 FGA"` |
| `xattr` | `"Agents cannot modify extended file attributes — blocked by Auth0 FGA"` |

### 4. Self-Modification / Scope Creep Prevention

| Blocked Command (substring match) | Rejection Reason |
|-----------------------------------|-----------------|
| `edit fga_policy` | `"Agents cannot modify their own authorization policy — blocked by Auth0 FGA"` |
| `edit main.py` | `"Agents cannot modify ShieldClaw gateway source code — blocked by Auth0 FGA"` |
| `edit evaluator.py` | `"Agents cannot modify ShieldBot evaluation logic — blocked by Auth0 FGA"` |
| `edit discord_bot.py` | `"Agents cannot modify the Discord bot — blocked by Auth0 FGA"` |
| `edit fga_client.py` | `"Agents cannot modify the FGA client — blocked by Auth0 FGA"` |
| `edit fga.py` | `"Agents cannot modify the FGA engine — blocked by Auth0 FGA"` |

| Blocked Path Prefix | Rejection Reason |
|---------------------|-----------------|
| `fga_policy` | `"Agents cannot access FGA policy files — blocked by Auth0 FGA"` |

### 5. Package Management

| Blocked Command (substring match) | Rejection Reason |
|-----------------------------------|-----------------|
| `pip install` | `"Agents cannot install Python packages — blocked by Auth0 FGA"` |
| `pip uninstall` | `"Agents cannot remove Python packages — blocked by Auth0 FGA"` |
| `npm install` | `"Agents cannot install Node packages — blocked by Auth0 FGA"` |
| `npm uninstall` | `"Agents cannot remove Node packages — blocked by Auth0 FGA"` |
| `brew install` | `"Agents cannot install system packages — blocked by Auth0 FGA"` |
| `brew uninstall` | `"Agents cannot remove system packages — blocked by Auth0 FGA"` |
| `apt install` | `"Agents cannot install system packages — blocked by Auth0 FGA"` |
| `apt remove` | `"Agents cannot remove system packages — blocked by Auth0 FGA"` |

### 6. Infrastructure / Service Management

| Blocked Command (substring match) | Rejection Reason |
|-----------------------------------|-----------------|
| `crontab` | `"Agents cannot create or modify cron jobs — blocked by Auth0 FGA"` |
| `systemctl` | `"Agents cannot manage system services — blocked by Auth0 FGA"` |
| `launchctl` | `"Agents cannot manage macOS services — blocked by Auth0 FGA"` |
| `nginx` | `"Agents cannot modify web server config — blocked by Auth0 FGA"` |
| `apache` | `"Agents cannot modify web server config — blocked by Auth0 FGA"` |
| `iptables` | `"Agents cannot modify firewall rules — blocked by Auth0 FGA"` |
| `ufw` | `"Agents cannot modify firewall rules — blocked by Auth0 FGA"` |
| `dns` | `"Agents cannot modify DNS records — blocked by Auth0 FGA"` |

| Blocked Path Prefix | Rejection Reason |
|---------------------|-----------------|
| `/etc/` | `"Agents cannot modify system configuration files — blocked by Auth0 FGA"` |
| `/usr/local/etc` | `"Agents cannot modify local system config — blocked by Auth0 FGA"` |

### 7. FGA Self-Granting / Privilege Escalation (Route-Based)

| Blocked Route Prefix | Rejection Reason |
|---------------------|-----------------|
| `/shieldclaw/fga/grant` | `"Agents cannot grant FGA permissions — blocked by Auth0 FGA"` |
| `/shieldclaw/fga/revoke` | `"Agents cannot revoke FGA permissions — blocked by Auth0 FGA"` |

### 8. Agent Management (Route + Command Combo)

| Blocked Command | Blocked Route Prefix | Rejection Reason |
|----------------|---------------------|-----------------|
| `revoke` | `/shieldclaw/agents/` | `"Agents cannot revoke other agents' registrations — blocked by Auth0 FGA"` |
| `rotate` | `/shieldclaw/agents/` | `"Agents cannot rotate other agents' keys — blocked by Auth0 FGA"` |

### 9. Admin Route Blocks (Route + Method Combos)

| Blocked Route Prefix | Blocked Method | Rejection Reason |
|---------------------|----------------|-----------------|
| `/shieldclaw/agents` | `POST` | `"Agents cannot register new agents — admin only"` |
| `/shieldclaw/agents` | `DELETE` | `"Agents cannot delete agent registrations — admin only"` |
| `/api/v1/admin` | (any) | `"Admin API is off-limits to agents"` |
| `/api/v1/config` | (any) | `"Config API is off-limits to agents"` |

### 10. Database Destructive Operations

| Blocked Command (substring match) | Rejection Reason |
|-----------------------------------|-----------------|
| `drop table` | `"Dropping tables is irreversible — not permitted for agents"` |
| `drop database` | `"Dropping databases is irreversible — not permitted for agents"` |
| `truncate` | `"Truncating tables is irreversible without a backup"` |
| `delete from` | `"Mass deletes require human approval"` |

### 11. Network / Data Exfiltration

| Blocked Command (regex substring) | Rejection Reason |
|-----------------------------------|-----------------|
| `curl.*--upload-file` | `"Uploading files via curl is not permitted"` |
| `wget.*-O` | `"Writing wget output to files is restricted"` |

### 12. Sensitive Email Operations

| Blocked Action Type (regex) | Rejection Reason |
|-----------------------------|-----------------|
| `email:delete_email` | `"Email deletion is a sensitive action — requires human approval"` |

| Blocked Command (substring) | Rejection Reason |
|-----------------------------|-----------------|
| `delete_email` | `"Email deletion is a sensitive action — requires human approval"` |

---

## Complete Allow Rules (Permitted Operations)

These are checked ONLY after all deny rules pass. First match permits the action.

### Safe Git Operations

| Allowed Command | Reason |
|----------------|--------|
| `git status` | Read-only git operation |
| `git log` | Read-only git operation |
| `git diff` | Read-only git operation |
| `git show` | Read-only git operation |
| `git branch` | Read-only git operation |
| `git fetch` | Read-only network operation |
| `git pull` | Safe merge operation |
| `git push` | Normal push (non-force) is permitted |
| `git commit` | Committing changes is permitted |
| `git add` | Staging files is permitted |
| `git checkout` | Switching branches is permitted |
| `git stash` | Stashing changes is permitted |

### Safe Shell Commands

| Allowed Command | Reason |
|----------------|--------|
| `ls` | Directory listing is safe |
| `cat` | Reading file contents is safe |
| `grep` | Searching file contents is safe |
| `find` | Finding files is safe |
| `echo` | Printing text is safe |
| `pwd` | Printing working directory is safe |
| `which` | Finding binaries is safe |
| `env` | Listing environment is permitted (data policy handles redaction) |
| `python` | Running Python scripts is permitted |
| `node` | Running Node scripts is permitted |
| `npm` | npm commands are permitted |
| `pip` | pip commands are permitted |
| `mkdir` | Creating directories is permitted |
| `cp` | Copying files is permitted |
| `mv` | Moving/renaming files is permitted |
| `touch` | Creating empty files is permitted |

### Safe Project Paths

| Allowed Path Prefix | Reason |
|--------------------|--------|
| `~/projects` | Projects directory is the primary workspace |
| `/tmp` | Temp directory is safe for agent use |

### Allowed API Routes

| Allowed Route Prefix | Reason |
|---------------------|--------|
| `/v1/chat` | Chat completions are the primary agent use case |
| `/v1/responses` | Response streaming is permitted |
| `/api/v1/hooks` | Hook invocation is permitted |
| `/api/v1/tools` | Tool invocation is permitted |
| `/health` | Health checks are always permitted |
| `/shieldclaw/whoami` | Identity introspection is always permitted |
| `/shieldclaw/backboard` | Dashboard access is permitted |

### Generic HTTP Method Allow

| Allowed Method | Reason |
|---------------|--------|
| `GET` | GET requests are generally safe (read-only) |

---

## Layer 2: Auth0 OpenFGA Authorization Model (`fga-model.fga`)

This is the relationship-based authorization model. It defines resource types, the relations users/agents can have on them, and how relations cascade.

### Schema Version: 1.1

### Resource Types and Relations

```
type user       — human users (Auth0 sub, e.g. "google-oauth2|123")
type agent      — AI agent identities (e.g. "agent_abc123def456")

type gateway    — ShieldClaw API gateway (singleton: "gateway:main")
  relations:
    admin:    [user]                        — full admin access
    operator: [user, agent] or admin        — can perform write operations
    viewer:   [user, agent] or operator     — can perform read operations

type agent_reg  — an agent registration resource
  relations:
    owner:       [user]                     — the human who registered the agent
    admin:       [user] or owner            — can manage the agent
    viewer:      [user, agent] or admin     — can view agent details
    can_revoke:  admin                      — can revoke the agent (derived from admin)
    can_rotate:  admin                      — can rotate the agent's keys (derived from admin)
    can_execute: [agent]                    — the agent itself can execute

type thread     — a Backboard.io conversation thread
  relations:
    owner:       [user]                     — thread creator
    participant: [user, agent] or owner     — can participate in the thread
    viewer:      [user, agent] or participant — can view the thread

type memory     — a user's Long-Term Memory profile
  relations:
    owner:  [user]                          — the human whose memory it is
    admin:  [user] or owner                 — can write to memory
    viewer: [user] or admin                 — can read memory

type file       — a file/directory accessible through the proxy
  relations:
    owner:       [user]                     — file owner
    editor:      [user, agent] or owner     — can edit the file
    viewer:      [user, agent] or editor    — can view the file
    can_delete:  [user] or owner            — can delete (humans only, not agents)
    can_execute: [user, agent] or owner     — can execute the file

type email      — email actions (send, read, delete) via Gmail integration
  relations:
    owner:      [user]                      — email account owner
    can_read:   [user, agent] or owner      — can read emails
    can_send:   [user, agent] or owner      — can send emails
    can_delete: [user] or owner             — can delete emails (humans only, not agents)

type approval   — a pending approval request
  relations:
    requester: [agent]                      — the agent that requested approval
    resolver:  [user]                       — the human who can approve/deny
    viewer:    [user, agent] or resolver or requester — can view the request
```

### Relation Cascading Rules

Relations cascade hierarchically: `owner ⊇ admin ⊇ operator/member ⊇ viewer`. This means:
- An `owner` automatically has `admin`, `operator`, and `viewer` permissions
- An `admin` automatically has `viewer` permissions
- A `participant` automatically has `viewer` permissions

### Key Security Design Decisions

- **`can_delete` on files and emails: `[user] or owner` — agents are EXCLUDED.** Agents cannot delete files or emails. Only humans can.
- **`can_execute` on agent_reg: `[agent]` — only the agent itself.** An agent can only execute as itself, not impersonate others.
- **`memory` viewer: `[user] or admin` — agents are EXCLUDED.** Agents cannot read user memory directly.

---

## Layer 2: Auth0 FGA Client (`fga_client.py`)

### Environment Variables Required

```
FGA_API_URL=https://api.us1.fga.dev           # OpenFGA API endpoint
FGA_STORE_ID=<your-store-id>                   # FGA store identifier
FGA_MODEL_ID=<your-model-id>                   # Authorization model ID
FGA_CLIENT_ID=<your-oauth-client-id>           # OAuth2 client credentials
FGA_CLIENT_SECRET=<your-oauth-client-secret>   # OAuth2 client secret
FGA_API_TOKEN_ISSUER=fga.us.auth0.com          # OAuth2 token issuer
FGA_API_AUDIENCE=https://api.us1.fga.dev/      # OAuth2 audience
```

If any required env var is missing, FGA checks are skipped and the YAML-only result is used.

### Public API Functions

```python
async def check_permission(user: str, relation: str, object_type: str, object_id: str, fail_open: bool = False) -> bool
    # Check if user has relation on object. Returns fail_open value on error.

async def grant_permission(user: str, relation: str, object_type: str, object_id: str) -> bool
    # Write a relationship tuple. Returns True on success.

async def revoke_permission(user: str, relation: str, object_type: str, object_id: str) -> bool
    # Delete a relationship tuple. Returns True on success.

async def list_relations(user: str, object_type: str, object_id: str, relations: list = None) -> list
    # Check which relations user holds. Tests each relation individually.

async def batch_grant(tuples: list) -> bool
    # Write multiple tuples at once. Each: {"user", "relation", "object_type", "object_id"}
```

### Failure Handling
- If FGA is unavailable or errors, returns `fail_open` value
- If YAML allowed but FGA denied: **YAML result wins** (YAML = deterministic baseline, FGA = additional check)
- If YAML denied: **immediate block** (FGA is never consulted)

---

## FGA Context Extraction (`_extract_fga_context`)

When the YAML layer doesn't hard-deny, the system extracts FGA context from the request to determine what Auth0 FGA relationship check to perform:

| Request Pattern | FGA Object Type | FGA Object ID | FGA Relation |
|----------------|----------------|---------------|-------------|
| `/shieldclaw/agents/{id}/revoke` | `agent_reg` | `{id}` | `can_revoke` |
| `/shieldclaw/agents/{id}/rotate` | `agent_reg` | `{id}` | `can_rotate` |
| `/shieldclaw/agents/{id}` (GET) | `agent_reg` | `{id}` | `viewer` |
| `POST /shieldclaw/agents` | `gateway` | `main` | `admin` |
| `/backboard/threads/{id}` | `thread` | `{id}` | `viewer` |
| `POST /ltm/memory/{user_id}` | `memory` | `{user_id}` | `admin` |
| `GET /ltm/memory/{user_id}` | `memory` | `{user_id}` | `viewer` |
| `/approval/{id}/resolve` | `approval` | `{id}` | `resolver` |
| `/approval/{id}` (view) | `approval` | `{id}` | `viewer` |
| File operation (DELETE) | `file` | `{normalized_path}` | `can_delete` |
| File operation (POST/PUT/PATCH) | `file` | `{normalized_path}` | `editor` |
| File operation (GET) | `file` | `{normalized_path}` | `viewer` |
| Email action (delete) | `email` | `mailbox` | `can_delete` |
| Email action (send) | `email` | `mailbox` | `can_send` |
| Email action (read/inbox/search) | `email` | `mailbox` | `can_read` |
| Generic POST/PUT/PATCH/DELETE | `gateway` | `main` | `operator` |

---

## Integration: How FGA Is Enforced in the Proxy (`main.py`)

### Request Flow Through the Proxy

Every request to the ShieldClaw gateway goes through this exact pipeline:

```
1. JWT Verification (Auth0)
   → Validates token signature, expiry, issuer, audience
   → Extracts scopes and identity claims
   → If invalid → 401 Unauthorized

2. Identity Classification
   → Determines if requestor is human or agent
   → Checks if agent is revoked → 403 if revoked

3. Scope Enforcement
   → Checks if token scopes allow the requested route
   → If insufficient scope → 403 Forbidden

4. FGA Policy Check (AGENTS ONLY)
   → Builds fga_payload: {"method": request.method, "path": request_path, "body": body_dict}
   → Builds action_type: "{method}:{resource}" (e.g., "post:chat", "get:tools")
   → Calls check_fga_full(agent_id, action_type, fga_payload, user_sub)
   → If not allowed → 403 Forbidden with [FGA] reason
   → IMPORTANT: The reason MUST state the block is due to Auth0's FGA restrictions

5. ShieldBot Evaluation (Risk Assessment)
   → Claude-powered evaluation of the action
   → Risk scoring (0-100)
   → Trust tier adjustment

6. Human Approval Loop (if needed)
   → If ShieldBot says "needs_confirmation" or "blocked"
   → Sends approval request to Discord admin
   → 90-second timeout, auto-deny on expiry

7. Forward Request to Upstream
   → Proxies the request to the actual API

8. Data Redaction (on response)
   → Redacts sensitive data from response body before returning to agent
```

### Proxy Code (Key Integration Point)

```python
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(request: Request, path: str):
    payload = await verify_token(request)
    identity = classify_identity(payload)

    # FGA check for agents
    if identity["is_agent"]:
        fga_payload = {"method": request.method, "path": request_path, "body": body_dict}
        action_type = f"{request.method.lower()}:{path_resource}"

        fga_result = await check_fga_full(agent_id, action_type, fga_payload, user_sub=identity.get("sub"))
        if not fga_result.allowed:
            raise HTTPException(status_code=403, detail=fga_result.reason)
```

### Agent Registration FGA Tuples

When a new agent is registered, these FGA tuples are written:

```python
await batch_grant([
    {
        "user": f"user:{owner_sub}",        # The human who registered the agent
        "relation": "owner",
        "object_type": "agent_reg",
        "object_id": agent_id
    },
    {
        "user": f"agent:{agent_id}",         # The agent itself
        "relation": "can_execute",
        "object_type": "agent_reg",
        "object_id": agent_id
    },
])
```

When an agent is revoked, these tuples are cleaned up:
```python
await revoke_permission(f"user:{agent['owner_sub']}", "owner", "agent_reg", agent_id)
await revoke_permission(f"agent:{agent_id}", "can_execute", "agent_reg", agent_id)
```

---

## Sensitive Tool Approval (Two-Layer)

For sensitive tools like `delete_email`, there is a two-layer approval process:

```python
async def _request_sensitive_approval(tool_name, tool_args):
    # Layer 1: Check Auth0 FGA
    fga_result = await check_fga_full(
        agent_id="backboard-interpreter",
        action_type=f"email:{tool_name}",
        payload=fga_payload,
    )
    if fga_result.allowed:
        return True  # FGA says OK, proceed

    # Layer 2: Human approval via Discord DM
    approval_id = str(uuid.uuid4())[:8].upper()
    event = asyncio.Event()
    _pending_approvals[approval_id] = {
        "event": event,
        "approved": None,
        "request": {
            "tool": tool_name,
            "args": tool_args,
            "approval_id": approval_id,
        }
    }
    # Wait up to 90 seconds for human approval
    await asyncio.wait_for(event.wait(), timeout=90.0)
    return bool(_pending_approvals[approval_id]["approved"])
```

---

## Data Redaction Layer (`data_policy.py`)

Separate from FGA authorization — controls what DATA agents can see in responses. Even if FGA allows the route, sensitive data is still redacted.

### Sensitive Data Categories and Their Regex Patterns

#### Category: `credentials`
**Description:** Passwords, API keys, tokens, secrets

| Regex Pattern |
|--------------|
| `(?i)(password\|passwd\|pwd)\s*[=:]\s*\S+` |
| `(?i)(secret\|client_secret)\s*[=:]\s*\S+` |
| `(?i)(api_key\|apikey\|api-key)\s*[=:]\s*\S+` |
| `(?i)(access_token\|auth_token\|bearer)\s*[=:]\s*\S+` |
| `(?i)(private_key\|private-key)[\s=:]+\S+` |
| `(?i)"(password\|secret\|api_key\|token\|private_key)"\s*:\s*"[^"]*"` |

**JSON field names redacted:** `password`, `passwd`, `secret`, `client_secret`, `api_key`, `apikey`, `access_token`, `auth_token`, `token`, `private_key`, `refresh_token`

#### Category: `pii`
**Description:** SSNs, emails, credit cards, phone numbers, DOB

| Regex Pattern |
|--------------|
| `\b\d{3}-\d{2}-\d{4}\b` (SSN) |
| `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z\|a-z]{2,}\b` (email) |
| `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b` (credit card) |
| `(?i)(phone\|tel\|mobile)\s*[=:]\s*[\d\s\-\+\(\)]+` |
| `(?i)(ssn\|social.security)\s*[=:]\s*\S+` |
| `(?i)(date.of.birth\|dob\|birthday)\s*[=:]\s*\S+` |

**JSON field names redacted:** `email`, `phone`, `ssn`, `social_security`, `date_of_birth`, `dob`, `address`, `home_address`

#### Category: `infra`
**Description:** Database URLs, connection strings, internal IPs

| Regex Pattern |
|--------------|
| `(?i)(database_url\|db_url\|connection_string)\s*[=:]\s*\S+` |
| `(?i)(redis_url\|mongo_uri\|postgres)\s*[=:]\s*\S+` |
| `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b` (IP addresses) |
| `(?i)(hostname\|internal_host)\s*[=:]\s*\S+` |

**JSON field names redacted:** `database_url`, `db_url`, `connection_string`, `redis_url`, `mongo_uri`, `internal_host`, `hostname`

#### Category: `financial`
**Description:** Bank accounts, balances, financial identifiers

| Regex Pattern |
|--------------|
| `(?i)(account.number\|acct.no\|routing.number)\s*[=:]\s*\S+` |
| `(?i)(balance\|salary\|income\|revenue)\s*[=:]\s*[\$\d,\.]+` |
| `(?i)(bank\|iban\|swift\|bic)\s*[=:]\s*\S+` |

**JSON field names redacted:** `account_number`, `routing_number`, `balance`, `salary`, `income`, `iban`, `swift`, `bank_account`

#### Category: `env_config`
**Description:** Cloud credentials, service API keys, env vars

| Regex Pattern |
|--------------|
| `(?i)(AWS_ACCESS_KEY\|AWS_SECRET)\s*[=:]\s*\S+` |
| `(?i)(GITHUB_TOKEN\|GH_TOKEN\|GITLAB_TOKEN)\s*[=:]\s*\S+` |
| `(?i)(OPENAI_API_KEY\|ANTHROPIC_API_KEY\|CLAUDE_API_KEY)\s*[=:]\s*\S+` |
| `(?i)(STRIPE_KEY\|TWILIO_SID)\s*[=:]\s*\S+` |

**JSON field names redacted:** `aws_access_key`, `aws_secret`, `github_token`, `openai_api_key`, `anthropic_api_key`, `stripe_key`

### Redaction Behavior

- **Agents: NO data access by default.** All categories are redacted. The default is `set()` (empty set).
- **Humans: FULL data access.** All categories are visible. Set is `{"credentials", "pii", "infra", "financial", "env_config"}`.
- Redacted values are replaced with `[REDACTED:{category}]` (e.g., `[REDACTED:credentials]`).
- Data access grants are set per-agent at registration time.
- Two redaction functions exist:
  - `redact_response()` — regex-based, scans raw response bytes
  - `redact_json_fields()` — JSON-aware, walks JSON keys and redacts known-sensitive field values

---

## Discord Bot Terminal Leak Prevention

The Discord bot has a separate regex filter that blocks responses containing operational/infrastructure details that should never leak to users:

```python
_TERMINAL_LEAK_RE = re.compile(
    r"(open your terminal|run `openclaw|use the CLI|type a command"
    r"|in your (terminal|shell|console)|openclaw pairing"
    r"|exec tool|allowlist|gateway restart|won't unlock|will not unlock"
    r"|open the Terminal app|openclaw gateway|security allowlist"
    r"|shell command|restart.*gateway|locked down)",
    re.IGNORECASE,
)
```

### Blocked Keywords in Discord Responses

| Keyword/Phrase | Why It's Blocked |
|---------------|-----------------|
| `open your terminal` | Prevents instructing users to run CLI commands |
| `` run `openclaw `` | Prevents leaking CLI tool usage |
| `use the CLI` | Prevents CLI disclosure |
| `type a command` | Prevents terminal instruction disclosure |
| `in your terminal` / `shell` / `console` | Prevents terminal instruction disclosure |
| `openclaw pairing` | Prevents pairing flow disclosure |
| `exec tool` | Prevents tool execution disclosure |
| `allowlist` | Prevents security config disclosure |
| `gateway restart` | Prevents infrastructure operation disclosure |
| `won't unlock` / `will not unlock` | Prevents security state disclosure |
| `open the Terminal app` | Prevents macOS terminal instruction |
| `openclaw gateway` | Prevents gateway detail disclosure |
| `security allowlist` | Prevents security config disclosure |
| `shell command` | Prevents shell command disclosure |
| `restart.*gateway` | Prevents infrastructure operation disclosure |
| `locked down` | Prevents security state disclosure |

When a match is found, the response is replaced with: `"I'm working on that — give me a moment."`

---

## FGA Admin Endpoints

These endpoints are only accessible to users with `gateway:admin` scope. Agents are blocked from these by the YAML deny rules.

### `POST /shieldclaw/fga/grant`
Grant an FGA permission (write a tuple).

**Request body:**
```json
{
  "user": "user:auth0|xxx" or "agent:agent_xxx",
  "relation": "owner",
  "object_type": "agent_reg",
  "object_id": "agent_abc123"
}
```

### `POST /shieldclaw/fga/revoke`
Revoke an FGA permission (delete a tuple).

**Request body:** Same format as grant.

### `POST /shieldclaw/fga/check`
Check if a user/agent has a specific permission.

**Request body:** Same format as grant. Returns `{"allowed": true/false}`.

### `GET /shieldclaw/fga/relations`
List all relations a user holds on an object.

---

## FGA Store Setup (`scripts/setup_fga.py`)

Initializes the Auth0 FGA store with the authorization model:

1. Parses `fga-model.fga` DSL into type definitions
2. Connects to the FGA store using env var credentials
3. Writes the authorization model via `write_authorization_model`
4. Writes bootstrap tuples (e.g., initial admin user gets `gateway:main` admin)

---

## Complete Security Coverage Summary

| Attack Vector | How FGA Prevents It |
|--------------|-------------------|
| **Credential theft** | Path prefix blocks on `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `.env` + data redaction of all credential patterns |
| **Privilege escalation** | `sudo`, `chmod`, `chown`, `chgrp` blocked. FGA grant/revoke routes blocked. |
| **Destructive operations** | `rm -rf`, `rm -r`, `git push --force`, `git reset --hard`, `git clean -f`, `drop table`, `drop database`, `truncate`, `delete from` all blocked |
| **Self-modification** | Cannot edit `fga_policy`, `main.py`, `evaluator.py`, `discord_bot.py`, `fga_client.py`, `fga.py` |
| **Package supply chain** | `pip install/uninstall`, `npm install/uninstall`, `brew install/uninstall`, `apt install/remove` all blocked |
| **Infrastructure tampering** | `crontab`, `systemctl`, `launchctl`, `nginx`, `apache`, `iptables`, `ufw`, `dns` blocked. `/etc/` and `/usr/local/etc` paths blocked. |
| **Data exfiltration** | `curl --upload-file` and `wget -O` blocked. Data redaction on all responses. |
| **Agent impersonation** | Each agent gets unique Auth0 M2M credentials. FGA tuples are agent-specific. |
| **Unauthorized email access** | `email:delete_email` blocked by FGA. `can_delete` relation excludes agents. Two-layer approval for sensitive ops. |
| **Agent self-registration** | `POST /shieldclaw/agents` blocked for agents. Only admins can register. |
| **FGA policy tampering** | `fga_policy` path blocked. `edit fga_policy` command blocked. Grant/revoke routes blocked. |
| **Terminal/CLI info leak** | Discord bot regex blocks responses mentioning terminals, CLI tools, gateway operations |
| **PII exposure** | Data redaction strips SSNs, emails, credit cards, phone numbers, DOB from agent responses |
| **Financial data exposure** | Data redaction strips bank accounts, balances, IBANs from agent responses |
| **Default-open vulnerability** | Default-deny policy. If no rule matches, the request is blocked. |

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `fga.py` | YAML policy engine + two-layer FGA check orchestrator |
| `fga_client.py` | Auth0 OpenFGA SDK wrapper (check, grant, revoke, list, batch) |
| `fga_policy.yaml` | Global YAML deny/allow rules (all blocked commands/keywords live here) |
| `fga-model.fga` | Auth0 FGA authorization model (resource types, relations, cascading) |
| `data_policy.py` | Data isolation + regex/JSON redaction engine |
| `main.py` | FastAPI proxy — integrates FGA into request pipeline |
| `scripts/setup_fga.py` | Initializes Auth0 FGA store with the authorization model |
| `jacob/shieldbot/discord_bot.py` | Discord integration + terminal leak prevention |
| `jacob/shieldbot/evaluator.py` | Claude-powered risk assessment engine |
| `policy_parser.py` | NLP → policy interpretation (translates natural language to scopes/data_access) |
