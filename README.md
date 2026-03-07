# ShieldClaw

Auth0 OAuth 2.0 security proxy for OpenClaw with **AI agent identity management**. Gives each AI coding agent (Claude Code, etc.) its own machine identity via Auth0, separate from the developer's personal credentials.

## Architecture

```
Developer (human JWT)  ──┐
                         ├──▶  ShieldClaw (:8443)  ──▶  OpenClaw (:18789)
AI Agent (M2M JWT)     ──┘        │
                                  ├── JWT validation (Auth0 JWKS)
                                  ├── Identity classification (human vs agent)
                                  ├── Scope-based route enforcement
                                  ├── Agent revocation checks
                                  └── Audit logging with identity type
```

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Fill in your Auth0 values (see .env.example)
```

Required env vars:
- `AUTH0_DOMAIN` — Your Auth0 tenant domain
- `AUTH0_CLIENT_ID` — ShieldClaw app client ID
- `AUTH0_AUDIENCE` — API audience identifier
- `AUTH0_MGMT_CLIENT_ID` — Auth0 Management API M2M app client ID
- `AUTH0_MGMT_CLIENT_SECRET` — Auth0 Management API M2M app client secret

### 3. Configure OpenClaw for trusted-proxy mode

```bash
openclaw config set gateway.auth.mode trusted-proxy
openclaw config set gateway.auth.trustedProxy.userHeader X-Auth0-User
openclaw config set gateway.auth.trustedProxy.requiredHeaders '["X-Auth0-User"]'
openclaw config set gateway.trustedProxies '["127.0.0.1"]'
```

### 4. Add scopes in Auth0

In your Auth0 dashboard, go to **Applications > APIs > ShieldClaw Gateway > Permissions** and add:

- `gateway:read` — Status and probe access
- `gateway:message` — Send/receive messages
- `gateway:tools` — Invoke tools
- `gateway:tools:exec` — Execute commands (dangerous)
- `gateway:admin` — Full admin access
- `gateway:canvas` — Canvas access

### 5. Run

```bash
# Terminal 1: OpenClaw gateway (loopback only)
openclaw gateway --bind loopback --port 18789

# Terminal 2: ShieldClaw proxy
python main.py
```

## Agent Identity Management

The core feature: AI agents get their own Auth0 M2M (machine-to-machine) credentials instead of running under the developer's identity.

### Register an agent

```bash
# As an admin, register a new agent identity
python cli.py register \
  --name "claude-code-dev" \
  --scopes "gateway:read,gateway:message,gateway:tools" \
  --token "$ADMIN_TOKEN"
```

This creates an Auth0 M2M application and returns a `client_id` + `client_secret` for the agent.

### Get an agent token

```bash
# The agent uses client credentials to get its own JWT
python cli.py get-agent-token \
  --client-id "AGENT_CLIENT_ID" \
  --client-secret "AGENT_CLIENT_SECRET" \
  --export
```

### Use the agent token

```bash
# Agent authenticates with its own identity
curl -H "Authorization: Bearer $AGENT_TOKEN" http://localhost:8443/v1/chat/completions \
  -d '{"messages": [...]}'
```

### Inspect identity

```bash
# Check what identity a token resolves to
python cli.py whoami --token "$TOKEN"
```

Returns:
```json
{
  "identity": {
    "sub": "abc123@clients",
    "is_agent": true,
    "identity_type": "agent",
    "agent_client_id": "abc123",
    "agent_id": "agent_1a2b3c4d5e6f",
    "agent_name": "claude-code-dev",
    "owner_sub": "auth0|developer_user_id"
  },
  "scopes": ["gateway:message", "gateway:read", "gateway:tools"]
}
```

### Manage agents

```bash
# List all agents
python cli.py list --token "$ADMIN_TOKEN"

# Revoke an agent (deletes Auth0 M2M app)
python cli.py revoke --agent-id agent_1a2b3c4d5e6f --token "$ADMIN_TOKEN"

# Rotate an agent's secret
python cli.py rotate-secret --agent-id agent_1a2b3c4d5e6f --token "$ADMIN_TOKEN"
```

### Programmatic usage (Python SDK)

```python
from agent_token_client import AgentTokenClient, AgentHTTPClient

# Create a token client for the agent
token_client = AgentTokenClient(
    client_id="AGENT_CLIENT_ID",
    client_secret="AGENT_CLIENT_SECRET",
)

# Wrap it in an HTTP client for easy authenticated requests
agent = AgentHTTPClient(token_client)
response = await agent.post("/v1/chat/completions", json={"messages": [...]})
```

## How it works

1. Client sends request with Auth0 JWT to ShieldClaw (:8443)
2. ShieldClaw validates JWT signature via Auth0 JWKS
3. **ShieldClaw classifies the identity as human or agent** (M2M tokens have `sub` ending in `@clients`)
4. If agent: checks revocation status in the agent registry
5. ShieldClaw checks token scopes against the requested route
6. Proxies to OpenClaw gateway (:18789) with identity headers:
   - `X-Auth0-User` — the `sub` claim
   - `X-Identity-Type` — `human` or `agent`
   - `X-Agent-Id` / `X-Agent-Name` / `X-Agent-Owner` (for agents)
7. Every request is audit-logged with identity type, agent name, and owner

## Why separate agent identity?

| Without (agent = you) | With (agent = its own identity) |
|---|---|
| No distinction in logs | Clear audit trail: "agent did X" vs "human did X" |
| Revoking agent = revoking yourself | Revoke agent without touching your credentials |
| Agent has all your permissions | Agent gets only the scopes you grant |
| No per-agent rate limiting | Each agent identity can be rate-limited independently |
| Can't scale to multiple agents | Each agent instance has its own identity |
