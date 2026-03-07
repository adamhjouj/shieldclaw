# ShieldClaw Security Layer — Implementation Plan

## What We're Building

Four additions to the existing ShieldClaw stack that together make ClawdBot
safe for non-technical users without requiring them to configure anything.

Current state:
- Auth0 JWT verification + agent registry in `main.py`
- Claude-powered Backboard evaluator in `jacob/shieldbot/evaluator.py`
- Data redaction layer (`data_policy.py`)
- Thread context + user memory in `jacob/shieldbot/`

These two sides (Auth0 proxy and Backboard evaluator) are currently
**disconnected** — the proxy doesn't call the evaluator. That gets fixed here.

---

## The Four Things

### 1. FGA — Fine-Grained Authorization (default-deny filesystem rules)

**What it does**

Before any request reaches OpenClaw, ShieldClaw checks whether ClawdBot is
allowed to touch the resource it's asking for. The model is default-deny:
if there is no explicit rule granting access, the answer is no.

Rules are stored as a simple policy file (YAML). Example:

```yaml
agent: clawdbot
deny:
  - path_prefix: ~/.ssh
  - path_prefix: ~/.aws
  - path_prefix: ~/.env
  - command: rm
  - command: git push --force
  - command: git reset --hard
  - command: drop table
allow:
  - path_prefix: ~/projects/current
  - command: git status
  - command: git log
  - command: ls
  - command: cat
  - command: grep
```

No rule matching the request = denied. This is not a prompt rule or a
suggestion to the LLM — it's a hard gate in the proxy layer that runs
before anything is forwarded to OpenClaw.

**Where it lives**

New file: `fga.py`
- `load_policy(agent_id)` — loads the policy for a given agent
- `check_fga(agent_id, action_type, payload)` — returns `allowed: bool, reason: str`

Called from `main.py` in the proxy route, after identity classification,
before forwarding to OpenClaw.

**What the user does**

Nothing. Default policy ships with the product and is safe out of the box.
Power users can edit the YAML if they want to loosen or tighten rules.

---

### 2. Backboard ↔ Proxy Integration (connecting the two halves)

**What it does**

Right now `jacob/shieldbot/evaluator.py` exists but `main.py` never calls it.
This step wires them together.

When a request comes through the proxy and passes Auth0 + FGA, it gets
sent to the Backboard evaluator before being forwarded to OpenClaw. If
Backboard returns `blocked`, the request is killed with a 403 and a clear
reason. If it returns `approved`, the request proceeds normally.

`needs_confirmation` is treated as `blocked` for now — since we removed CIBA,
there's no approval flow. The design keeps `needs_confirmation` in the
Decision type so it can be wired to a UI later without changing the evaluator.

**The request flow after this change:**

```
Incoming request
  → Auth0 JWT verification          (who is this?)
  → FGA policy check                (can this identity touch this resource?)
  → Backboard Claude evaluation     (is this specific action safe right now?)
  → Forward to OpenClaw             (actually do the thing)
  → Data redaction on response      (strip sensitive fields from response)
  → Return to caller
```

**What changes**

`main.py` proxy route — after scope check, before forwarding:
```python
# Extract action context from request body
# Call jacob.shieldbot.evaluator.evaluate(ActionRequest(...))
# If decision.status == "blocked" → 403
# If decision.status == "needs_confirmation" → 403 (pending UI)
# If decision.status == "approved" → proceed
```

The `ActionRequest` is built from:
- `user_id` = `identity["sub"]`
- `session_id` = from `X-Session-Id` header or generated
- `action_type` = inferred from request path + method
- `payload` = request body (what ClawdBot is actually trying to do)

**What the user does**

Nothing. This runs invisibly. They just notice ClawdBot stops doing
destructive things.

---

### 3. Auth0 Actions — Automatic Role + Trust Tier Assignment

**What it does**

When ClawdBot mints a new token (client_credentials flow), an Auth0 Action
runs automatically and bakes two custom claims into the JWT:

- `x-trust-tier`: `"high"` / `"medium"` / `"low"` — based on the agent's
  registration metadata (what type of agent is it, what scopes it has)
- `x-agent-type`: `"coding"` / `"readonly"` / `"admin"` — the role assigned
  at registration time

These claims travel with every request. ShieldClaw reads them from the JWT
without hitting Auth0 again.

The trust tier feeds back into Backboard — a `low` tier agent gets a stricter
system prompt injected into the Claude evaluation:

```
trust_tier=low  →  Claude told: "Be very conservative. Treat ambiguous
                   actions as blocked."
trust_tier=high →  Claude told: "Normal thresholds apply."
```

The tier also self-adjusts per-session: if an agent accumulates 3+ blocked
decisions in a session, its effective tier for that session drops one level.
This is tracked in `thread_manager` and doesn't require a token re-issue.

**What the Auth0 Action looks like (JavaScript, runs in Auth0)**

```javascript
exports.onExecuteClientCredentialsExchange = async (event, api) => {
  const scopes = event.accessToken.scopes || [];

  let agentType = "readonly";
  if (scopes.includes("gateway:tools:exec")) agentType = "admin";
  else if (scopes.includes("gateway:tools")) agentType = "coding";

  let trustTier = "medium";
  if (agentType === "readonly") trustTier = "high";
  if (agentType === "admin") trustTier = "low";

  api.accessToken.setCustomClaim("x-trust-tier", trustTier);
  api.accessToken.setCustomClaim("x-agent-type", agentType);
};
```

No user interaction. The right trust tier is set automatically based on
what the agent registered for.

**What changes in the codebase**

`main.py` — `classify_identity()` reads `x-trust-tier` and `x-agent-type`
from the JWT payload and includes them in the identity dict.

`jacob/shieldbot/evaluator.py` — `_build_prompt()` receives trust tier and
appends a tier-appropriate instruction line to the system context.

**What the user does**

Nothing. They pick an agent type at registration ("coding assistant",
"read-only assistant") and the trust tier is set automatically.

---

### 4. RAR-style Audit Context (rich request metadata on every decision)

**What it does**

Every Backboard decision — approved or blocked — gets logged with full
context: exactly what was attempted, what path, what command, what the
Claude reasoning was, and what trust tier was active at the time.

This serves two purposes:
1. **Transparency for users** — the `/shieldclaw/audit` endpoint returns
   a human-readable log of everything ClawdBot did and tried to do.
   Non-technical users can see "ClawdBot tried to delete 47 files and was
   blocked" without understanding the technical details.
2. **Feed for trust tier adjustment** — the audit log is what the
   session-level tier degradation reads from.

**What changes**

`jacob/shieldbot/logger.py` — extend `log_decision()` to store:
- full request payload (what was attempted)
- FGA verdict (was it stopped before even reaching Claude?)
- Claude's raw reasoning
- active trust tier at time of decision
- session block count at time of decision

New endpoint in `main.py`:
```
GET /shieldclaw/audit
```
Returns the last N decisions for the current identity, formatted for humans.
Agents see their own log. Admins see all logs.

**What the user does**

Nothing required. They can optionally hit `/shieldclaw/audit` in a dashboard
to see what ClawdBot has been up to.

---

## File Map — What Gets Created or Changed

| File | Change |
|------|--------|
| `fga.py` | New — policy loader + check function |
| `fga_policy.yaml` | New — default deny/allow rules |
| `main.py` | Add FGA check + Backboard call in proxy route; read trust tier from JWT |
| `jacob/shieldbot/evaluator.py` | Accept trust tier, adjust system prompt accordingly |
| `jacob/shieldbot/logger.py` | Extend log entries with full audit context |
| Auth0 dashboard | New Action on client_credentials trigger (manual step) |

---

## Build Order

1. **FGA** — standalone, no dependencies on other steps. Immediately stops
   ClawdBot from touching protected paths regardless of what else is happening.

2. **Backboard integration** — wire `main.py` → `evaluator.py`. Depends on
   FGA being in place so the evaluator only sees requests that passed the
   hard rules first.

3. **Trust tier via Auth0 Actions** — add JWT claims, read them in the proxy,
   pass them to the evaluator. Depends on integration being live so the tier
   actually affects decisions.

4. **Audit log + endpoint** — extend the logger and expose the endpoint.
   Can be done at any point but most useful once all three other pieces are
   generating decisions.

---

## What a Non-Technical User Experiences After This

They set up ClawdBot, pick "coding assistant" as the type, and use it normally.

- ClawdBot reads files, writes code, runs tests — all invisible, all automatic.
- ClawdBot tries to delete a folder — blocked silently, logged.
- ClawdBot tries to push to a protected branch — blocked silently, logged.
- ClawdBot has a weird session where it keeps trying risky things — its trust
  tier drops automatically, Claude gets stricter, more things get blocked.
- User checks `/shieldclaw/audit` — sees a clear list of what ClawdBot did
  and what it was stopped from doing.

Zero configuration. Zero approval prompts. Just a safer agent by default.
