# Auth0 FGA (Fine-Grained Authorization) — ShieldClaw

## Overview

ShieldClaw uses a **two-layer authorization system**:

1. **YAML Policy** (`fga_policy.yaml`) — Fast, local, deterministic command/path rules
2. **Auth0 FGA** (OpenFGA) — Remote, relationship-based fine-grained checks

The YAML layer blocks dangerous commands (rm -rf, sudo, etc.) immediately.
The FGA layer checks if a user/agent has the right relationship to a specific resource.

## Authorization Model

The model is defined in `fga-model.fga` and covers these types:

| Type | Description | Relations |
|------|-------------|-----------|
| `user` | Human users (Auth0 sub) | — |
| `agent` | AI agent identities | — |
| `gateway` | The ShieldClaw API gateway (singleton: `gateway:main`) | admin, operator, viewer |
| `agent_reg` | An agent registration | owner, admin, viewer, can_revoke, can_rotate, can_execute |
| `thread` | A Backboard.io conversation thread | owner, participant, viewer |
| `memory` | A user's LTM memory profile | owner, admin, viewer |
| `file` | A file/directory accessible through the proxy | owner, editor, viewer, can_delete, can_execute |
| `approval` | A pending approval request | requester, resolver, viewer |

### Relation Inheritance

Relations cascade downward:
- `owner` implies `admin` implies `member`/`participant` implies `viewer`
- `can_revoke` and `can_rotate` are derived from `admin`

### Tuple Format

```
user:auth0|69abfa319f6b0b2cda5668a0  owner  agent_reg:agent_abc123def456
agent:agent_abc123def456              can_execute  agent_reg:agent_abc123def456
user:auth0|69abfa319f6b0b2cda5668a0  admin  gateway:main
```

## Setup

### 1. Configure Environment

Add these to your `.env`:

```bash
FGA_API_URL=https://api.us1.fga.dev
FGA_STORE_ID=your_store_id
FGA_API_TOKEN_ISSUER=fga.us.auth0.com
FGA_API_AUDIENCE=https://api.us1.fga.dev/
FGA_CLIENT_ID=your_fga_client_id
FGA_CLIENT_SECRET=your_fga_client_secret
```

### 2. Write the Authorization Model

```bash
python scripts/setup_fga.py
```

This will:
- Parse `fga-model.fga`
- Write the model to your FGA store
- Print the model ID
- Write a bootstrap tuple (gateway:admin for AUTH0_TEST_USER_ID)

### 3. Set the Model ID

Copy the printed model ID into your `.env`:

```bash
FGA_MODEL_ID=01KK55XXXXXXXXXXXXX
```

### 4. Restart ShieldClaw

```bash
python main.py
```

## How It Works

### Request Flow

```
Agent request arrives
    |
    v
[JWT Verification] -> identity, scopes
    |
    v
[Scope Check] -> route-level RBAC
    |
    v
[YAML Policy] -> command/path deny/allow rules
    |
    v
[Auth0 FGA] -> relationship-based check (does agent have relation on resource?)
    |
    v
[ShieldBot] -> Claude risk evaluation
    |
    v
[Proxy to OpenClaw]
```

### Automatic Tuple Writes

When an agent is registered via `POST /shieldclaw/agents`:
- `user:{owner_sub}` gets `owner` on `agent_reg:{agent_id}`
- `agent:{agent_id}` gets `can_execute` on `agent_reg:{agent_id}`

When an agent is revoked via `POST /shieldclaw/agents/{id}/revoke`:
- Both tuples above are deleted

### Fail Behavior

- If FGA is unreachable and YAML **allowed** the action -> **fail open** (proceed)
- If FGA is unreachable and YAML **denied** the action -> **fail closed** (block)
- If FGA env vars are missing -> FGA layer is skipped entirely, YAML-only

## Admin API Endpoints

All require `gateway:admin` scope in the JWT.

### Grant Permission

```bash
curl -X POST http://localhost:8443/shieldclaw/fga/grant \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user": "user:auth0|69abfa319f6b0b2cda5668a0",
    "relation": "admin",
    "object_type": "gateway",
    "object_id": "main"
  }'
```

### Revoke Permission

```bash
curl -X POST http://localhost:8443/shieldclaw/fga/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user": "agent:agent_abc123",
    "relation": "can_execute",
    "object_type": "agent_reg",
    "object_id": "agent_abc123"
  }'
```

### Check Permission

```bash
curl -X POST http://localhost:8443/shieldclaw/fga/check \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user": "agent:agent_abc123",
    "relation": "can_execute",
    "object_type": "agent_reg",
    "object_id": "agent_abc123"
  }'
# -> {"allowed": true, ...}
```

### List Relations

```bash
curl "http://localhost:8443/shieldclaw/fga/relations?user=user:auth0|xxx&object_type=agent_reg&object_id=agent_abc123" \
  -H "Authorization: Bearer $TOKEN"
# -> {"relations": ["owner", "admin", "can_revoke", "can_rotate"]}
```

## Tuple Reference by Resource Type

| Resource | Tuple Example | When Written |
|----------|---------------|--------------|
| Gateway admin | `user:auth0\|xxx admin gateway:main` | `setup_fga.py` bootstrap |
| Agent owner | `user:auth0\|xxx owner agent_reg:agent_abc` | Agent registration |
| Agent executor | `agent:agent_abc can_execute agent_reg:agent_abc` | Agent registration |
| Thread participant | `user:auth0\|xxx participant thread:thread_123` | Manual grant |
| File editor | `agent:agent_abc editor file:src_main_py` | Manual grant |
| Approval resolver | `user:auth0\|xxx resolver approval:ABC12345` | Manual grant |

## Files

| File | Purpose |
|------|---------|
| `fga_client.py` | OpenFGA SDK wrapper with check/grant/revoke helpers |
| `fga.py` | Two-layer engine: YAML + Auth0 FGA |
| `fga-model.fga` | Authorization model DSL |
| `fga_policy.yaml` | Local YAML deny/allow rules |
| `scripts/setup_fga.py` | Writes the model to the FGA store |
| `FGA.md` | This file |
