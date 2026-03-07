import asyncio
import json
import os
import secrets
import sys
import time
import uuid
import logging
import sqlite3
import urllib.parse
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse
from jose import jwt, JWTError

from agent_identity import AgentRegistry, AgentRegistration, Auth0ManagementClient
from data_policy import redact_response, get_data_policy_summary, SENSITIVE_PATTERNS
from policy_parser import parse_policy
from vault import vault
from fga import check_fga
from jacob.shieldbot import evaluate, ActionRequest
from jacob.shieldbot import logger as shieldbot_logger
from jacob.shieldbot import config as shieldbot_config
from jacob.shieldbot import backboard_client
from jacob.shieldbot import backboard as shieldbot_backboard

load_dotenv()

# ---------------------------------------------------------------------------
# Dev bypass — run with DEV_BYPASS=true to skip Auth0 JWT verification.
# Use `python main.py --register` to print a fake agent credential and exit.
# ---------------------------------------------------------------------------

DEV_BYPASS = os.getenv("DEV_BYPASS", "").lower() in ("1", "true", "yes")
SHIELDBOT_BYPASS = os.getenv("SHIELDBOT_BYPASS", "").lower() in ("1", "true", "yes")

# Fake dev agent pre-seeded when DEV_BYPASS is on
_DEV_AGENT = {
    "agent_id": "agent_dev000000",
    "agent_name": "dev-agent",
    "auth0_client_id": "dev-client-id",
    "owner_sub": "dev-user@devlocal",
    "scopes": ["gateway:read", "gateway:message", "gateway:tools", "gateway:canvas", "gateway:admin"],
    "created_at": 0.0,
    "data_access": [],  # populated after SENSITIVE_PATTERNS is imported
    "revoked": False,
}
_DEV_TOKEN = "dev-bypass-token"

# ---------------------------------------------------------------------------
# Human-in-the-loop approval store
# ---------------------------------------------------------------------------
# approval_id → {"event": asyncio.Event, "approved": bool | None, "request": dict}
_pending_approvals: dict[str, dict] = {}


def _maybe_register_and_exit():
    """If invoked with --register, print dev credentials and exit."""
    if "--register" not in sys.argv:
        return
    if not DEV_BYPASS:
        print("ERROR: DEV_BYPASS env var must be set to use --register.")
        sys.exit(1)
    _DEV_AGENT["data_access"] = list(SENSITIVE_PATTERNS.keys())
    print("\n=== ShieldClaw Dev Registration ===")
    print(f"  DEV_BYPASS  : enabled")
    print(f"  agent_id    : {_DEV_AGENT['agent_id']}")
    print(f"  agent_name  : {_DEV_AGENT['agent_name']}")
    print(f"  client_id   : {_DEV_AGENT['auth0_client_id']}")
    print(f"  owner_sub   : {_DEV_AGENT['owner_sub']}")
    print(f"  scopes      : {_DEV_AGENT['scopes']}")
    print(f"  data_access : {_DEV_AGENT['data_access']}")
    print(f"\n  Use this header on every request:")
    print(f"    Authorization: Bearer {_DEV_TOKEN}")
    print(f"\n  The dev agent token bypasses Auth0 JWT verification entirely.")
    print(f"  ShieldBot still runs — set SHIELDBOT_BYPASS=true to also skip it.\n")
    sys.exit(0)


_maybe_register_and_exit()

# --- Config ---

AUTH0_DOMAIN = vault.get("AUTH0_DOMAIN", "codcodingcode.ca.auth0.com")
AUTH0_CLIENT_ID = vault.get("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = vault.get("AUTH0_CLIENT_SECRET", "")
AUTH0_AUDIENCE = vault.get("AUTH0_AUDIENCE", "https://shieldclaw-gateway")
AUTH0_ALGORITHMS = ["RS256"]
OPENCLAW_UPSTREAM = vault.get("OPENCLAW_UPSTREAM", "http://127.0.0.1:18789")
OPENCLAW_TOKEN = vault.get("OPENCLAW_TOKEN", "shieldclaw-local-token")
SHIELDCLAW_PORT = int(vault.get("SHIELDCLAW_PORT", "8443"))

JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
ISSUER = f"https://{AUTH0_DOMAIN}/"

# ---------------------------------------------------------------------------
# Discord ↔ Auth0 token store
# Maps Discord user ID → {"access_token": str, "expires_at": float, "sub": str}
# ---------------------------------------------------------------------------
_discord_auth0_tokens: dict[str, dict] = {}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("shieldclaw")

# --- Agent Infrastructure ---

agent_registry = AgentRegistry()
auth0_mgmt = Auth0ManagementClient()

# --- JWKS Cache ---

_jwks_cache: Optional[dict] = None
_jwks_fetched_at: float = 0
JWKS_CACHE_TTL = 3600  # re-fetch signing keys every hour


async def get_jwks() -> dict:
    """Fetch and cache Auth0 JWKS (JSON Web Key Set) for JWT signature verification."""
    global _jwks_cache, _jwks_fetched_at
    if _jwks_cache and (time.time() - _jwks_fetched_at) < JWKS_CACHE_TTL:
        return _jwks_cache
    async with httpx.AsyncClient() as client:
        resp = await client.get(JWKS_URL)
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_fetched_at = time.time()
        logger.info("Refreshed JWKS from Auth0")
    return _jwks_cache


def find_rsa_key(jwks: dict, kid: str) -> Optional[dict]:
    """Find the RSA key matching the JWT's kid header."""
    for key in jwks.get("keys", []):
        if key["kid"] == kid:
            return key
    return None


# --- Scope-to-Route Enforcement ---

ROUTE_SCOPES: dict[str, set[str]] = {
    "/api/v1/hooks":              {"gateway:message"},
    "/api/v1/tools/invoke":       {"gateway:tools"},
    "/v1/chat/completions":       {"gateway:message"},
    "/v1/responses":              {"gateway:message"},
    "/__openclaw__/canvas":       {"gateway:canvas"},
    "/__openclaw__/a2ui":         {"gateway:canvas"},
}

# Routes that require the dangerous exec scope
EXEC_ROUTE_PREFIXES = ["/api/v1/exec"]

# Admin-only routes
ADMIN_ROUTE_PREFIXES = ["/api/v1/config", "/api/v1/admin"]


def scopes_to_trust_tier(scopes: set[str]) -> str:
    """Derive ShieldBot trust tier from token scopes.

    gateway:tools:exec or gateway:admin → low  (very conservative)
    gateway:tools or gateway:message    → medium
    gateway:read only                   → high  (approve freely)
    """
    if "gateway:tools:exec" in scopes or "gateway:admin" in scopes:
        return "low"
    if "gateway:tools" in scopes or "gateway:message" in scopes:
        return "medium"
    return "high"


def build_action_request(
    identity: dict,
    method: str,
    path: str,
    body: bytes,
    payload_claims: dict,
) -> ActionRequest:
    """Build a ShieldBot ActionRequest from an HTTP proxy request."""
    user_id = identity.get("agent_id") or identity.get("user_sub", "unknown")
    session_id = payload_claims.get("sub", "unknown")

    path_parts = path.strip("/").split("/")
    resource = path_parts[1] if len(path_parts) > 1 else (path_parts[0] if path_parts else "unknown")
    action_type = f"{method.lower()}:{resource}"

    try:
        body_dict = json.loads(body) if body else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        body_dict = {}

    # For chat completions, don't pass raw message content to ShieldBot —
    # user message text is not an agent action and triggers false positives.
    if action_type == "post:chat":
        shieldbot_payload = {"method": method, "path": path, "message_count": len(body_dict.get("messages", []))}
    else:
        shieldbot_payload = {"method": method, "path": path, "body": body_dict}

    return ActionRequest(
        user_id=user_id,
        session_id=session_id,
        action_type=action_type,
        payload=shieldbot_payload,
    )


def check_scopes(token_scopes: set[str], request_path: str) -> Optional[str]:
    """Return an error message if the token lacks required scopes for this route.

    Only hard-blocks admin routes (management operations). Everything else is
    allowed through to ShieldBot for risk evaluation — agents need full hands.
    """
    # Admin/management routes still require explicit admin scope
    for prefix in ADMIN_ROUTE_PREFIXES:
        if request_path.startswith(prefix):
            if "gateway:admin" not in token_scopes:
                return f"Scope 'gateway:admin' required for {request_path}"

    return None


# --- JWT Verification ---

async def verify_token(request: Request) -> dict:
    """Extract, verify, and decode the Auth0 JWT from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")

    # Dev bypass: accept any Bearer dev-* token without hitting Auth0
    # When X-Discord-User-Id is present, mint a per-user identity so each
    # Discord user gets their own Auth0-style sub, session, and audit trail.
    if DEV_BYPASS and auth_header == f"Bearer {_DEV_TOKEN}":
        discord_uid = request.headers.get("X-Discord-User-Id", "")
        if discord_uid:
            client_id = f"discord-{discord_uid}"
        else:
            client_id = _DEV_AGENT["auth0_client_id"]
        scopes = " ".join(_DEV_AGENT["scopes"])
        return {
            "sub": f"{client_id}@clients",
            "gty": "client-credentials",
            "azp": client_id,
            "scope": scopes,
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400,
            "iss": ISSUER,
            "aud": AUTH0_AUDIENCE,
        }

    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = auth_header[len("Bearer "):]

    # Decode header to find key id
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token header")

    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(status_code=401, detail="Token missing kid header")

    # Find matching RSA key from JWKS
    jwks = await get_jwks()
    rsa_key = find_rsa_key(jwks, kid)
    if not rsa_key:
        # Key might have rotated, force refresh
        global _jwks_fetched_at
        _jwks_fetched_at = 0
        jwks = await get_jwks()
        rsa_key = find_rsa_key(jwks, kid)
        if not rsa_key:
            raise HTTPException(status_code=401, detail="Unable to find signing key")

    # Verify and decode
    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=AUTH0_ALGORITHMS,
            audience=AUTH0_AUDIENCE,
            issuer=ISSUER,
        )
    except jwt.ExpiredSignatureError:
        _record_debug_event("auth_failed", {"reason": "token_expired", "kid": kid})
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTClaimsError as e:
        _record_debug_event("auth_failed", {"reason": "invalid_claims", "detail": str(e), "kid": kid})
        raise HTTPException(status_code=401, detail=f"Invalid claims: {e}")
    except JWTError as e:
        _record_debug_event("auth_failed", {"reason": "jwt_error", "detail": str(e), "kid": kid})
        raise HTTPException(status_code=401, detail=f"Token verification failed: {e}")

    _record_debug_event("auth_ok", {"sub": payload.get("sub"), "kid": kid, "aud": payload.get("aud")})
    return payload


# --- Audit Logging ---

def classify_identity(payload: dict) -> dict:
    """Classify whether a JWT belongs to a human user or an AI agent.

    Auth0 M2M (client_credentials) tokens have a 'sub' of '<client_id>@clients'
    and lack a 'gty' or have gty='client-credentials'. Human tokens have a normal sub.
    """
    sub = payload.get("sub", "unknown")
    gty = payload.get("gty", "")
    azp = payload.get("azp", "")

    is_agent = (
        sub.endswith("@clients")
        or gty == "client-credentials"
    )

    identity = {
        "sub": sub,
        "is_agent": is_agent,
        "identity_type": "agent" if is_agent else "human",
    }

    if is_agent:
        # Extract client_id from sub (format: <client_id>@clients)
        client_id = sub.replace("@clients", "") if sub.endswith("@clients") else azp
        identity["agent_client_id"] = client_id

        # Dev bypass: inject the fake agent record directly, skip registry lookup
        if DEV_BYPASS and (
            client_id == _DEV_AGENT["auth0_client_id"]
            or client_id.startswith("discord-")
        ):
            _DEV_AGENT["data_access"] = list(SENSITIVE_PATTERNS.keys())
            discord_uid = client_id.removeprefix("discord-") if client_id.startswith("discord-") else ""
            identity["agent_id"] = f"agent_{discord_uid}" if discord_uid else _DEV_AGENT["agent_id"]
            identity["agent_name"] = f"discord-user-{discord_uid}" if discord_uid else _DEV_AGENT["agent_name"]
            identity["owner_sub"] = f"discord:{discord_uid}" if discord_uid else _DEV_AGENT["owner_sub"]
            return identity

        # Look up agent in registry for metadata
        agent_record = agent_registry.get_by_client_id(client_id)
        if agent_record:
            identity["agent_id"] = agent_record["agent_id"]
            identity["agent_name"] = agent_record["agent_name"]
            identity["owner_sub"] = agent_record["owner_sub"]
            if agent_record.get("revoked"):
                identity["revoked"] = True
        else:
            identity["agent_id"] = f"unregistered:{client_id}"
            identity["agent_name"] = "unknown"
    else:
        identity["user_sub"] = sub

    return identity


def log_request(identity: dict, scopes: set[str], method: str, path: str, status: int):
    id_type = identity["identity_type"]
    sub = identity["sub"]
    extra = ""
    if identity["is_agent"]:
        extra = f" agent_name={identity.get('agent_name', '?')} owner={identity.get('owner_sub', '?')}"
    logger.info(
        f"type={id_type} sub={sub}{extra} scopes={','.join(sorted(scopes))} {method} {path} -> {status}"
    )


# --- App ---

app = FastAPI(title="ShieldClaw", description="Auth0 OAuth security proxy for OpenClaw")


@app.get("/health")
async def health():
    return {"status": "ok", "proxy": "shieldclaw"}


# --- Agent Management Endpoints ---

@app.post("/shieldclaw/agents")
async def register_agent(request: Request):
    """Register a new AI agent identity. Requires gateway:admin scope."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    identity = classify_identity(payload)

    if "gateway:admin" not in token_scopes:
        raise HTTPException(status_code=403, detail="Scope 'gateway:admin' required to register agents")

    body = await request.json()
    agent_name = body.get("agent_name")
    description = body.get("description", f"ShieldClaw agent: {agent_name}")
    policy_text = body.get("policy")
    scopes_explicit = "scopes" in body
    data_access_explicit = "data_access" in body
    scopes = body.get("scopes", ["gateway:read", "gateway:message"])
    data_access = body.get("data_access", [])

    if not agent_name:
        raise HTTPException(status_code=400, detail="agent_name is required")

    # Natural language policy parsing
    policy_interpretation = None
    if policy_text:
        parsed = await parse_policy(policy_text)
        policy_interpretation = {
            "original_policy": policy_text,
            "interpreted_scopes": parsed["scopes"],
            "interpreted_data_access": parsed["data_access"],
            "confidence": parsed["confidence"],
            "reasoning": parsed["reasoning"],
            "warnings": parsed["warnings"],
            "override_note": [],
        }
        if not scopes_explicit:
            scopes = parsed["scopes"]
        else:
            policy_interpretation["override_note"].append(
                "scopes: explicit values used instead of parsed"
            )
        if not data_access_explicit:
            data_access = parsed["data_access"]
        else:
            policy_interpretation["override_note"].append(
                "data_access: explicit values used instead of parsed"
            )

    # Validate data_access categories
    valid_categories = set(SENSITIVE_PATTERNS.keys())
    invalid = set(data_access) - valid_categories
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid data_access categories: {invalid}. Valid: {valid_categories}",
        )

    # Create Auth0 M2M application for this agent
    auth0_app = await auth0_mgmt.create_agent_application(agent_name, description, scopes)

    agent_id = f"agent_{uuid.uuid4().hex[:12]}"
    reg = AgentRegistration(
        agent_id=agent_id,
        agent_name=agent_name,
        auth0_client_id=auth0_app["client_id"],
        owner_sub=identity["sub"],
        scopes=scopes,
        created_at=time.time(),
        data_access=data_access,
    )
    agent_registry.register(reg)

    logger.info(f"Agent registered: {agent_id} ({agent_name}) by {identity['sub']}")

    response = {
        "agent_id": agent_id,
        "agent_name": agent_name,
        "client_id": auth0_app["client_id"],
        "client_secret": auth0_app["client_secret"],
        "scopes": scopes,
        "data_access": data_access,
        "message": "Store the client_secret securely. It cannot be retrieved again.",
    }
    if policy_interpretation is not None:
        response["policy_interpretation"] = policy_interpretation
    return response


@app.get("/shieldclaw/agents")
async def list_agents(request: Request):
    """List registered agents. Admins see all; others see their own."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    identity = classify_identity(payload)

    if "gateway:admin" in token_scopes:
        agents = agent_registry.list_agents()
    else:
        agents = agent_registry.list_agents(owner_sub=identity["sub"])

    # Strip sensitive fields
    safe_agents = []
    for a in agents:
        safe_agents.append({
            "agent_id": a["agent_id"],
            "agent_name": a["agent_name"],
            "owner_sub": a["owner_sub"],
            "scopes": a["scopes"],
            "created_at": a["created_at"],
            "revoked": a["revoked"],
        })

    return {"agents": safe_agents}


@app.post("/shieldclaw/agents/{agent_id}/revoke")
async def revoke_agent(agent_id: str, request: Request):
    """Revoke an agent's access. Owner or admin can revoke."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    identity = classify_identity(payload)

    agent = agent_registry.get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    is_owner = agent["owner_sub"] == identity["sub"]
    is_admin = "gateway:admin" in token_scopes
    if not (is_owner or is_admin):
        raise HTTPException(status_code=403, detail="Only the agent owner or an admin can revoke")

    agent_registry.revoke(agent_id)

    # Also delete the Auth0 M2M application
    await auth0_mgmt.delete_agent_application(agent["auth0_client_id"])

    logger.info(f"Agent revoked: {agent_id} by {identity['sub']}")
    return {"status": "revoked", "agent_id": agent_id}


@app.post("/shieldclaw/agents/{agent_id}/rotate-secret")
async def rotate_agent_secret(agent_id: str, request: Request):
    """Rotate an agent's client secret. Owner or admin only."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    identity = classify_identity(payload)

    agent = agent_registry.get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    is_owner = agent["owner_sub"] == identity["sub"]
    is_admin = "gateway:admin" in token_scopes
    if not (is_owner or is_admin):
        raise HTTPException(status_code=403, detail="Only the agent owner or an admin can rotate secrets")

    new_creds = await auth0_mgmt.rotate_agent_secret(agent["auth0_client_id"])

    logger.info(f"Agent secret rotated: {agent_id} by {identity['sub']}")
    return {
        "agent_id": agent_id,
        "client_id": new_creds["client_id"],
        "client_secret": new_creds["client_secret"],
        "message": "Store the new client_secret securely. The old secret is now invalid.",
    }


@app.get("/shieldclaw/whoami")
async def whoami(request: Request):
    """Return the identity classification for the current token."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    identity = classify_identity(payload)
    return {
        "identity": identity,
        "scopes": sorted(token_scopes),
    }


@app.get("/shieldclaw/data-policy")
async def data_policy(request: Request):
    """Show what data categories this identity can see vs what gets redacted."""
    payload = await verify_token(request)
    identity = classify_identity(payload)

    if not identity["is_agent"]:
        return {
            "identity_type": "human",
            "message": "Humans see all data — it's your data.",
            "data_policy": get_data_policy_summary(
                set(SENSITIVE_PATTERNS.keys())  # all categories visible
            ),
        }

    _client_id = identity.get("agent_client_id", "")
    if DEV_BYPASS and (_client_id == _DEV_AGENT["auth0_client_id"] or _client_id.startswith("discord-")):
        agent_data_access = set(SENSITIVE_PATTERNS.keys())
    else:
        agent_record = agent_registry.get_by_client_id(_client_id)
        agent_data_access = set(agent_record.get("data_access", [])) if agent_record else set()

    return {
        "identity_type": "agent",
        "agent_name": identity.get("agent_name"),
        "message": "This agent's responses are filtered. Categories not granted are redacted.",
        "data_policy": get_data_policy_summary(agent_data_access),
    }


@app.get("/shieldclaw/identity-report")
async def identity_report(request: Request):
    """Show the security layers of the current token's identity,
    comparing what an agent can do vs what its owner (human) can do."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    identity = classify_identity(payload)

    # All possible scopes and what they unlock
    all_scopes = {
        "gateway:read": {
            "description": "Status and probe access",
            "routes": ["/api/v1/* (read-only)"],
            "risk": "low",
        },
        "gateway:message": {
            "description": "Send/receive messages",
            "routes": ["/v1/chat/completions", "/v1/responses", "/api/v1/hooks"],
            "risk": "medium",
        },
        "gateway:tools": {
            "description": "Invoke tools",
            "routes": ["/api/v1/tools/invoke"],
            "risk": "medium",
        },
        "gateway:tools:exec": {
            "description": "Execute arbitrary commands",
            "routes": ["/api/v1/exec/*"],
            "risk": "critical",
        },
        "gateway:admin": {
            "description": "Full admin access",
            "routes": ["/api/v1/config/*", "/api/v1/admin/*", "/shieldclaw/agents"],
            "risk": "critical",
        },
        "gateway:canvas": {
            "description": "Canvas/UI access",
            "routes": ["/__openclaw__/canvas", "/__openclaw__/a2ui"],
            "risk": "low",
        },
    }

    # Build the scope comparison
    granted = []
    denied = []
    for scope, info in all_scopes.items():
        entry = {"scope": scope, **info}
        if scope in token_scopes:
            granted.append(entry)
        else:
            denied.append(entry)

    # Token metadata
    token_info = {
        "issued_at": payload.get("iat"),
        "expires_at": payload.get("exp"),
        "issuer": payload.get("iss"),
        "audience": payload.get("aud"),
    }
    if payload.get("exp"):
        remaining = payload["exp"] - time.time()
        token_info["expires_in_seconds"] = max(0, int(remaining))
        token_info["expires_in_human"] = (
            f"{int(remaining // 3600)}h {int((remaining % 3600) // 60)}m"
            if remaining > 0 else "EXPIRED"
        )

    report = {
        "identity": identity,
        "token": token_info,
        "security_layers": {
            "layer_1_authentication": {
                "description": "JWT signature verified against Auth0 JWKS",
                "status": "passed",
                "method": "RS256 asymmetric signature",
                "issuer": ISSUER,
            },
            "layer_2_identity_classification": {
                "description": "Token classified as human or agent",
                "identity_type": identity["identity_type"],
                "detection_method": "sub ending in @clients / gty=client-credentials",
            },
            "layer_3_revocation_check": {
                "description": "Agent identities checked against revocation registry",
                "applicable": identity["is_agent"],
                "status": "revoked" if identity.get("revoked") else "active",
            },
            "layer_4_scope_enforcement": {
                "description": "Token scopes checked against route permissions",
                "granted_scopes": sorted(token_scopes),
                "accessible_routes": granted,
                "blocked_routes": denied,
            },
            "layer_5_upstream_headers": {
                "description": "Identity headers forwarded to OpenClaw",
                "headers_sent": {
                    "X-Auth0-User": identity["sub"],
                    "X-Identity-Type": identity["identity_type"],
                    **({"X-Agent-Id": identity.get("agent_id", ""),
                        "X-Agent-Name": identity.get("agent_name", ""),
                        "X-Agent-Owner": identity.get("owner_sub", "")}
                       if identity["is_agent"] else {}),
                },
            },
            "layer_6_audit": {
                "description": "Every request logged with full identity context",
                "log_fields": ["identity_type", "sub", "scopes", "method", "path", "status"]
                + (["agent_name", "owner_sub"] if identity["is_agent"] else []),
            },
        },
    }

    # If this is an agent, show comparison with owner's potential access
    if identity["is_agent"]:
        owner_sub = identity.get("owner_sub", "unknown")

        report["isolation_comparison"] = {
            "description": "How this agent's access compares to its owner",
            "agent": {
                "sub": identity["sub"],
                "name": identity.get("agent_name"),
                "scopes": sorted(token_scopes),
                "credential_type": "M2M client_credentials (short-lived JWT)",
                "revocable_independently": True,
                "can_be_rate_limited": True,
                "actions_attributed_to": f"agent:{identity.get('agent_name', '?')}",
            },
            "owner": {
                "sub": owner_sub,
                "scopes": "(owner's scopes determined by their own token, not visible here)",
                "credential_type": "Human interactive login (Authorization Code flow)",
                "note": "Owner typically has broader access including gateway:admin",
            },
            "security_boundaries": [
                {
                    "boundary": "Separate credentials",
                    "detail": "Agent has its own client_id/secret, never sees owner's password or tokens",
                },
                {
                    "boundary": "Scoped permissions",
                    "detail": f"Agent limited to: {', '.join(sorted(token_scopes))}",
                },
                {
                    "boundary": "Independent revocation",
                    "detail": "Revoking agent does not affect owner's access",
                },
                {
                    "boundary": "Distinct audit trail",
                    "detail": f"All actions logged under sub={identity['sub']}, not owner's sub",
                },
                {
                    "boundary": "Token lifetime",
                    "detail": f"Agent token expires in {token_info.get('expires_in_human', '?')}; "
                              "must re-authenticate via client_credentials",
                },
            ],
        }

    return report


# --- Debug Endpoint ---

# Ring buffer of recent auth events for the debug view
_debug_log: list[dict] = []
_DEBUG_LOG_MAX = 50

def _record_debug_event(event: str, detail: dict):
    _debug_log.append({"ts": time.time(), "event": event, **detail})
    if len(_debug_log) > _DEBUG_LOG_MAX:
        _debug_log.pop(0)


@app.get("/shieldclaw/debug")
async def debug():
    """No-auth debug endpoint: shows Auth0 config, JWKS cache, OpenClaw reachability, and recent auth events."""
    # Check OpenClaw reachability
    openclaw_ok = False
    openclaw_error = None
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{OPENCLAW_UPSTREAM}/health")
            openclaw_ok = r.status_code < 500
    except Exception as e:
        openclaw_error = str(e)

    # JWKS cache status
    jwks_cached = _jwks_cache is not None
    jwks_age = int(time.time() - _jwks_fetched_at) if jwks_cached else None
    jwks_key_count = len(_jwks_cache.get("keys", [])) if jwks_cached else 0

    return {
        "shieldclaw": "running",
        "config": {
            "auth0_domain": AUTH0_DOMAIN,
            "audience": AUTH0_AUDIENCE,
            "algorithms": AUTH0_ALGORITHMS,
            "openclaw_upstream": OPENCLAW_UPSTREAM,
            "port": SHIELDCLAW_PORT,
        },
        "jwks_cache": {
            "cached": jwks_cached,
            "age_seconds": jwks_age,
            "ttl_seconds": JWKS_CACHE_TTL,
            "key_count": jwks_key_count,
            "url": JWKS_URL,
        },
        "openclaw": {
            "reachable": openclaw_ok,
            "error": openclaw_error,
        },
        "agent_registry": {
            "total_agents": len(agent_registry.list_agents()),
            "active_agents": len([a for a in agent_registry.list_agents() if not a["revoked"]]),
        },
        "recent_auth_events": list(reversed(_debug_log)),
    }


# --- Backboard Dashboard ---

@app.get("/shieldclaw/backboard", response_class=HTMLResponse)
async def backboard_dashboard():
    """Serve the Backboard audit log dashboard."""
    dashboard_path = __file__.replace("main.py", "dashboard.html")
    with open(dashboard_path) as f:
        return HTMLResponse(content=f.read())


@app.get("/shieldclaw/backboard/log")
async def backboard_log():
    """Return the merged audit log as JSON.

    Merges the rich trace log (has input_summary, matched_rules, etc.) with the
    simpler audit log (has Claude reasoning). Trace log entries are normalized to
    the same field names the dashboard expects.
    """
    from jacob.shieldbot import backboard as _bb

    # Normalize trace log entries → dashboard field names
    trace_entries = []
    for t in _bb.get_trace_log():
        trace_entries.append({
            "timestamp":          t.get("timestamp", ""),
            "user_id":            t.get("user_id", ""),
            "session_id":         t.get("session_id", ""),
            "thread_id":          t.get("thread_id", ""),
            "trace_id":           t.get("trace_id", ""),
            "action_type":        t.get("action_type", ""),
            "payload":            t.get("payload", {}),
            "status":             t.get("final_decision", "unknown"),
            "risk_score":         t.get("risk_score", 0),
            "reason":             t.get("final_reason", ""),
            "factors":            t.get("detected_risk_factors", []),
            "matched_rules":      t.get("matched_rules", []),
            "matched_preferences":t.get("matched_preferences", []),
            "trust_tier":         t.get("trust_tier", "medium"),
            "input_summary":      t.get("input_summary", ""),
            "output_summary":     t.get("output_summary", ""),
            "reasoning":          None,  # enriched below from audit log
        })

    # Index audit log by (session_id, action_type) to pull in Claude reasoning
    audit_index: dict[tuple, dict] = {}
    for a in shieldbot_logger.get_audit_log():
        key = (a.get("session_id", ""), a.get("action_type", ""))
        audit_index[key] = a

    for entry in trace_entries:
        key = (entry["session_id"], entry["action_type"])
        audit = audit_index.get(key)
        if audit:
            entry["reasoning"] = audit.get("reasoning")
            # Fill payload from audit if missing in trace
            if not entry["payload"]:
                entry["payload"] = audit.get("payload", {})

    # Fall back to raw audit log if trace log is empty (e.g. non-evaluator paths)
    if not trace_entries:
        raw = shieldbot_logger.get_audit_log()
        for a in raw:
            a.setdefault("trace_id", "")
            a.setdefault("input_summary", "")
            a.setdefault("output_summary", "")
            a.setdefault("matched_rules", [])
            a.setdefault("matched_preferences", [])
        trace_entries = raw

    return JSONResponse(content={"log": trace_entries})


@app.get("/shieldclaw/backboard/config")
async def backboard_get_config():
    """Return current Shieldbot runtime config."""
    return JSONResponse(content=shieldbot_config.get_config())


@app.post("/shieldclaw/backboard/config")
async def backboard_set_config(request: Request):
    """Update Shieldbot runtime config.

    Body: { "eval_mode": "think" | "fast" }
    """
    body = await request.json()
    if "eval_mode" in body:
        try:
            shieldbot_config.set_eval_mode(body["eval_mode"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    return JSONResponse(content=shieldbot_config.get_config())


# --- Human-in-the-loop approval endpoints ---

def _check_internal_token(request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    if token not in (OPENCLAW_TOKEN, _DEV_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/shieldclaw/approval/pending")
async def approval_get_pending(request: Request):
    """Discord bot polls this to get pending approval requests."""
    _check_internal_token(request)
    pending = []
    for approval_id, entry in list(_pending_approvals.items()):
        if entry["approved"] is None:
            pending.append({"approval_id": approval_id, "request": entry["request"]})
    return JSONResponse(content={"pending": pending})


@app.post("/shieldclaw/approval/{approval_id}/resolve")
async def approval_resolve(approval_id: str, request: Request):
    """Discord bot calls this when admin clicks Approve or Deny."""
    _check_internal_token(request)
    body = await request.json()
    approved: bool = bool(body.get("approved", False))

    entry = _pending_approvals.get(approval_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Approval not found or already resolved")

    entry["approved"] = approved
    entry["event"].set()
    return JSONResponse(content={"ok": True, "approved": approved})


@app.post("/shieldclaw/clear-session")
async def clear_session(request: Request):
    """Discord bot calls this on /clear to wipe ShieldBot session history and trust tier."""
    from jacob.shieldbot import thread_manager as _tm
    _check_internal_token(request)
    body = await request.json()
    session_id = body.get("session_id", "")
    if session_id:
        _tm.clear_session(session_id)
    return JSONResponse(content={"ok": True})


# --- Auth0 OAuth flow for Discord users ---

# Pending OAuth states: state_nonce → {"discord_user_id": str, "created_at": float}
_oauth_pending: dict[str, dict] = {}


@app.get("/shieldclaw/auth/discord/login")
async def discord_auth0_login(discord_user_id: str):
    """Generate an Auth0 login URL for a Discord user.

    The Discord bot redirects users here. Auth0 Universal Login handles
    the actual authentication, then redirects back to our callback.
    """
    if not AUTH0_CLIENT_ID or not AUTH0_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Auth0 client credentials not configured")

    state = secrets.token_urlsafe(32)
    _oauth_pending[state] = {
        "discord_user_id": discord_user_id,
        "created_at": time.time(),
    }

    # Clean up stale pending states (older than 10 minutes)
    cutoff = time.time() - 600
    stale = [k for k, v in _oauth_pending.items() if v["created_at"] < cutoff]
    for k in stale:
        _oauth_pending.pop(k, None)

    callback_url = f"http://localhost:{SHIELDCLAW_PORT}/shieldclaw/auth/discord/callback"
    params = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": AUTH0_CLIENT_ID,
        "redirect_uri": callback_url,
        "scope": "openid profile email",
        "audience": AUTH0_AUDIENCE,
        "state": state,
    })
    auth_url = f"https://{AUTH0_DOMAIN}/authorize?{params}"

    return JSONResponse(content={"login_url": auth_url})


@app.get("/shieldclaw/auth/discord/callback", response_class=HTMLResponse)
async def discord_auth0_callback(code: str = "", state: str = "", error: str = ""):
    """Auth0 redirects here after the user logs in."""
    if error:
        return HTMLResponse(content=f"<h2>Login failed</h2><p>{error}</p>", status_code=400)

    pending = _oauth_pending.pop(state, None)
    if not pending:
        return HTMLResponse(content="<h2>Invalid or expired login link</h2><p>Please try again from Discord.</p>", status_code=400)

    discord_user_id = pending["discord_user_id"]
    callback_url = f"http://localhost:{SHIELDCLAW_PORT}/shieldclaw/auth/discord/callback"

    # Exchange authorization code for tokens
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            resp = await c.post(
                f"https://{AUTH0_DOMAIN}/oauth/token",
                json={
                    "grant_type": "authorization_code",
                    "client_id": AUTH0_CLIENT_ID,
                    "client_secret": AUTH0_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": callback_url,
                },
            )
            resp.raise_for_status()
            token_data = resp.json()
    except Exception as e:
        logger.error(f"Auth0 token exchange failed for discord user {discord_user_id}: {e}")
        return HTMLResponse(content=f"<h2>Login failed</h2><p>Token exchange error: {e}</p>", status_code=500)

    access_token = token_data.get("access_token", "")
    expires_in = token_data.get("expires_in", 86400)

    # Decode the access token to get the sub (no verification needed here —
    # we just got it directly from Auth0's token endpoint over HTTPS)
    try:
        unverified = jwt.get_unverified_claims(access_token)
        sub = unverified.get("sub", "unknown")
    except Exception:
        sub = "unknown"

    _discord_auth0_tokens[discord_user_id] = {
        "access_token": access_token,
        "expires_at": time.time() + expires_in,
        "sub": sub,
    }

    _record_debug_event("discord_auth0_login", {
        "discord_user_id": discord_user_id,
        "sub": sub,
        "expires_in": expires_in,
    })
    logger.info(f"Discord user {discord_user_id} authenticated via Auth0 as {sub}")

    return HTMLResponse(content=(
        "<h2>Authenticated!</h2>"
        "<p>You can close this tab and go back to Discord.</p>"
        f"<p>Logged in as: <code>{sub}</code></p>"
    ))


@app.get("/shieldclaw/auth/discord/token/{discord_user_id}")
async def discord_auth0_get_token(discord_user_id: str, request: Request):
    """Internal endpoint: Discord bot fetches a user's stored Auth0 token."""
    _check_internal_token(request)
    stored = _discord_auth0_tokens.get(discord_user_id)
    if not stored:
        return JSONResponse(content={"authenticated": False})
    if stored["expires_at"] < time.time():
        _discord_auth0_tokens.pop(discord_user_id, None)
        return JSONResponse(content={"authenticated": False, "reason": "expired"})
    return JSONResponse(content={
        "authenticated": True,
        "access_token": stored["access_token"],
        "sub": stored["sub"],
        "expires_at": stored["expires_at"],
    })


# --- Auth0 Debug Dashboard ---

@app.get("/shieldclaw/auth0", response_class=HTMLResponse)
async def auth0_dashboard():
    """Serve the Auth0 debug dashboard."""
    dashboard_path = __file__.replace("main.py", "auth0_dashboard.html")
    with open(dashboard_path) as f:
        return HTMLResponse(content=f.read())


@app.get("/shieldclaw/auth0/status")
async def auth0_status():
    """No-auth: return full Auth0 config, JWKS health, recent auth events, agent registry, Backboard connectivity."""
    import platform, sys

    # JWKS health
    jwks_cached = _jwks_cache is not None
    jwks_age = int(time.time() - _jwks_fetched_at) if jwks_cached else None
    jwks_key_ids = [k.get("kid") for k in _jwks_cache.get("keys", [])] if jwks_cached else []

    # OpenClaw reachability
    openclaw_ok = False
    openclaw_error = None
    openclaw_latency_ms = None
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            t0 = time.time()
            r = await client.get(f"{OPENCLAW_UPSTREAM}/health")
            openclaw_latency_ms = round((time.time() - t0) * 1000, 1)
            openclaw_ok = r.status_code < 500
    except Exception as e:
        openclaw_error = str(e)

    # Backboard reachability
    from jacob.shieldbot import config as _sc
    backboard_ok = False
    backboard_error = None
    backboard_latency_ms = None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            t0 = time.time()
            r = await client.get(
                f"{_sc.BACKBOARD_BASE_URL}/health",
                headers={"X-API-Key": _sc.BACKBOARD_API_KEY},
            )
            backboard_latency_ms = round((time.time() - t0) * 1000, 1)
            backboard_ok = r.status_code < 500
    except Exception as e:
        backboard_error = str(e)

    # Agent registry summary
    all_agents = agent_registry.list_agents()
    active_agents = [a for a in all_agents if not a["revoked"]]
    revoked_agents = [a for a in all_agents if a["revoked"]]

    return {
        "timestamp": time.time(),
        "system": {
            "python": sys.version,
            "platform": platform.platform(),
            "shieldclaw_port": SHIELDCLAW_PORT,
            "uptime_since": _server_start_time,
            "uptime_seconds": round(time.time() - _server_start_time, 1),
        },
        "auth0": {
            "domain": AUTH0_DOMAIN,
            "audience": AUTH0_AUDIENCE,
            "algorithms": AUTH0_ALGORITHMS,
            "issuer": ISSUER,
            "jwks_url": JWKS_URL,
            "client_id_configured": bool(AUTH0_CLIENT_ID),
        },
        "jwks": {
            "cached": jwks_cached,
            "age_seconds": jwks_age,
            "ttl_seconds": JWKS_CACHE_TTL,
            "key_count": len(jwks_key_ids),
            "key_ids": jwks_key_ids,
            "healthy": jwks_cached,
        },
        "openclaw": {
            "url": OPENCLAW_UPSTREAM,
            "reachable": openclaw_ok,
            "latency_ms": openclaw_latency_ms,
            "error": openclaw_error,
        },
        "backboard": {
            "url": _sc.BACKBOARD_BASE_URL,
            "api_key_set": bool(_sc.BACKBOARD_API_KEY),
            "reachable": backboard_ok,
            "latency_ms": backboard_latency_ms,
            "error": backboard_error,
            "think_model": _sc.BACKBOARD_THINK_MODEL,
            "fast_model": _sc.BACKBOARD_FAST_MODEL,
            "current_eval_mode": _sc.get_eval_mode(),
        },
        "agent_registry": {
            "total": len(all_agents),
            "active": len(active_agents),
            "revoked": len(revoked_agents),
            "agents": [
                {
                    "agent_id": a["agent_id"],
                    "agent_name": a["agent_name"],
                    "owner_sub": a["owner_sub"],
                    "scopes": a["scopes"],
                    "revoked": a["revoked"],
                    "created_at": a["created_at"],
                }
                for a in all_agents
            ],
        },
        "route_scopes": {k: list(v) for k, v in ROUTE_SCOPES.items()},
        "recent_auth_events": list(reversed(_debug_log)),
        "scope_definitions": {
            "gateway:read": {"risk": "low", "description": "Status and probe access"},
            "gateway:message": {"risk": "medium", "description": "Send/receive messages to AI"},
            "gateway:tools": {"risk": "medium", "description": "Invoke tools"},
            "gateway:tools:exec": {"risk": "critical", "description": "Execute arbitrary commands"},
            "gateway:canvas": {"risk": "low", "description": "Canvas/UI access"},
            "gateway:admin": {"risk": "critical", "description": "Full admin + agent management"},
        },
    }


# Track server start time for uptime display
_server_start_time = time.time()


# --- Backboard.io Threads & Memory Endpoints ---

@app.get("/shieldclaw/backboard/threads")
async def backboard_threads(request: Request):
    """List all Backboard.io threads for this assistant."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    if "gateway:admin" not in token_scopes:
        raise HTTPException(status_code=403, detail="Scope 'gateway:admin' required")
    try:
        threads = backboard_client.list_threads()
        return JSONResponse(content={"threads": threads})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/shieldclaw/backboard/threads/{thread_id}")
async def backboard_thread_detail(thread_id: str, request: Request):
    """Get a Backboard.io thread with all its messages."""
    payload = await verify_token(request)
    try:
        thread = backboard_client.get_thread(thread_id)
        return JSONResponse(content=thread)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/shieldclaw/backboard/memories")
async def backboard_memories(request: Request):
    """List all Backboard.io memories for the Shieldbot assistant."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    if "gateway:admin" not in token_scopes:
        raise HTTPException(status_code=403, detail="Scope 'gateway:admin' required")
    try:
        memories = backboard_client.list_memories()
        return JSONResponse(content=memories)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.post("/shieldclaw/backboard/chat")
async def backboard_chat(request: Request):
    """Chat with Shieldbot via Backboard.io. Creates a thread, sends message, returns response.

    Body: { "message": "I want to export the customer database", "session_id": "optional" }
    """
    payload = await verify_token(request)
    identity = classify_identity(payload)
    body = await request.json()
    message = body.get("message", "")
    session_id = body.get("session_id", f"chat-{identity['sub']}")

    if not message:
        raise HTTPException(status_code=400, detail="message is required")

    try:
        thread = shieldbot_backboard.get_or_create_thread(
            user_id=identity.get("agent_id", identity["sub"]),
            session_id=session_id,
        )
        resp = backboard_client.add_message(
            thread["thread_id"],
            message,
            memory="Auto",
            send_to_llm="true",
        )
        return JSONResponse(content={
            "response": resp.get("content", ""),
            "thread_id": thread["thread_id"],
            "session_id": session_id,
        })
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/shieldclaw/backboard/status")
async def backboard_status():
    """No-auth: Backboard.io connection status and memory stats."""
    status = {
        "connected": backboard_client.is_configured(),
        "base_url": backboard_client.BASE_URL,
        "assistant_id": backboard_client.ASSISTANT_ID,
    }
    try:
        memories = backboard_client.list_memories()
        status["memory_count"] = memories.get("total_count", len(memories.get("memories", [])))
    except Exception as e:
        status["memory_error"] = str(e)
    return JSONResponse(content=status)


# ---------------------------------------------------------------------------
# Backboard Long-Term Memory (LTM) Middleware
# ---------------------------------------------------------------------------

class MemoryMode(str, Enum):
    """Controls how Backboard memory is read/written for a user session."""
    OFF = "off"
    READONLY = "readonly"
    AUTO = "auto"
    FORCE = "force"

    def to_backboard_param(self) -> str:
        return {
            MemoryMode.OFF: "Off",
            MemoryMode.READONLY: "Readonly",
            MemoryMode.AUTO: "Auto",
            MemoryMode.FORCE: "On",
        }[self]


class BackboardInterpreter:
    """Middleware routing Discord messages through Backboard LTM before
    Clawdbot/OpenClaw.

    Message lifecycle:
        Discord user message
        → main.py middleware (this class)
        → Backboard assistant + thread (reads/writes LTM)
        → optional tool call → Clawdbot/OpenClaw executes task
        → result submitted back to Backboard
        → final assistant response returned to Discord
    """

    ALLOWED_TOOLS: frozenset[str] = frozenset({
        "execute_clawdbot_task",
        "read_file",
        "list_files",
        "search_files",
        "chat_completions",
    })
    TOOL_TIMEOUT = 45
    DEFAULT_MEMORY_MODE = MemoryMode.AUTO
    MAX_TOOL_ITERATIONS = 5

    LTM_SYSTEM_PROMPT = (
        "You are ShieldClaw's Long-Term Memory assistant. You sit between "
        "Discord users and Clawdbot/OpenClaw.\n\n"
        "RESPONSIBILITIES:\n"
        "1. MEMORY — Maintain structured operational context per user: response "
        "style preferences, trusted/denied tools, recurring task patterns, "
        "channel sensitivity levels, and whether execution requires approval. "
        "NEVER store raw chat history.\n"
        "2. TOOL DISPATCH — When the user's request requires Clawdbot/OpenClaw, "
        "use the execute_clawdbot_task tool with a clear task description.\n"
        "3. CONTEXT — Use stored memories to personalise responses and tool "
        "selection.\n"
        "4. SAFETY — Respect denied-tool lists. Never expose infrastructure "
        "details to users.\n\n"
        "When you discover a user's operational preference, persist it as "
        "structured memory so it survives across sessions."
    )

    def __init__(self) -> None:
        self._api_key = os.getenv("BACKBOARD_API_KEY", shieldbot_config.BACKBOARD_API_KEY)
        self._base_url = os.getenv("BACKBOARD_BASE_URL", shieldbot_config.BACKBOARD_BASE_URL)
        self._assistant_id = os.getenv("BACKBOARD_ASSISTANT_ID", "")
        self._model_provider = os.getenv("BACKBOARD_MODEL_PROVIDER", "anthropic")
        self._model_name = os.getenv(
            "BACKBOARD_MODEL_NAME", shieldbot_config.BACKBOARD_THINK_MODEL,
        )
        self._db_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "backboard_ltm.db",
        )
        self._init_db()
        logger.info("[BackboardInterpreter] Initialised — db=%s", self._db_path)

    # ── SQLite persistence ────────────────────────────────────────────────

    def _init_db(self) -> None:
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS thread_map ("
                "  discord_user_id      TEXT NOT NULL,"
                "  discord_channel_id   TEXT NOT NULL,"
                "  guild_id             TEXT DEFAULT '',"
                "  backboard_thread_id  TEXT NOT NULL,"
                "  backboard_assistant_id TEXT NOT NULL,"
                "  created_at           TEXT NOT NULL,"
                "  PRIMARY KEY (discord_user_id, discord_channel_id)"
                ")"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS user_memory ("
                "  discord_user_id         TEXT PRIMARY KEY,"
                "  memory_mode             TEXT DEFAULT 'auto',"
                "  preferred_response_style TEXT DEFAULT '',"
                "  trusted_tools           TEXT DEFAULT '[]',"
                "  denied_tools            TEXT DEFAULT '[]',"
                "  recurring_patterns      TEXT DEFAULT '[]',"
                "  channel_sensitivity     TEXT DEFAULT '{}',"
                "  requires_approval       INTEGER DEFAULT 0,"
                "  frequent_doc_sources    TEXT DEFAULT '[]',"
                "  last_updated            TEXT DEFAULT ''"
                ")"
            )
            conn.commit()
        finally:
            conn.close()

    def _db(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    # ── Assistant management ──────────────────────────────────────────────

    async def get_or_create_assistant(self) -> str:
        if self._assistant_id:
            return self._assistant_id

        headers = {"X-API-Key": self._api_key}
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.get(f"{self._base_url}/assistants", headers=headers)
            if resp.is_success:
                for a in resp.json():
                    if a.get("name") == "shieldclaw-ltm":
                        self._assistant_id = a["assistant_id"]
                        logger.info(
                            "[BackboardInterpreter] Reusing assistant %s",
                            self._assistant_id,
                        )
                        return self._assistant_id

            resp = await c.post(
                f"{self._base_url}/assistants",
                json={
                    "name": "shieldclaw-ltm",
                    "system_prompt": self.LTM_SYSTEM_PROMPT,
                },
                headers=headers,
            )
            resp.raise_for_status()
            self._assistant_id = resp.json()["assistant_id"]
            logger.info(
                "[BackboardInterpreter] Created assistant %s", self._assistant_id,
            )
        return self._assistant_id

    # ── Thread mapping ────────────────────────────────────────────────────

    async def get_or_create_thread(
        self, discord_user_id: str, channel_id: str, guild_id: str = "",
    ) -> str:
        with self._db() as conn:
            row = conn.execute(
                "SELECT backboard_thread_id FROM thread_map "
                "WHERE discord_user_id = ? AND discord_channel_id = ?",
                (discord_user_id, channel_id),
            ).fetchone()
            if row:
                return row[0]

        assistant_id = await self.get_or_create_assistant()
        headers = {"X-API-Key": self._api_key}
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(
                f"{self._base_url}/assistants/{assistant_id}/threads",
                json={},
                headers=headers,
            )
            resp.raise_for_status()
            thread_id = resp.json()["thread_id"]

        with self._db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO thread_map "
                "(discord_user_id, discord_channel_id, guild_id, "
                "backboard_thread_id, backboard_assistant_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    discord_user_id, channel_id, guild_id,
                    thread_id, assistant_id,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()

        logger.info(
            "[BackboardInterpreter] Thread %s for user=%s channel=%s",
            thread_id, discord_user_id, channel_id,
        )
        return thread_id

    # ── User memory ───────────────────────────────────────────────────────

    def load_user_memory(self, discord_user_id: str) -> dict:
        with self._db() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM user_memory WHERE discord_user_id = ?",
                (discord_user_id,),
            ).fetchone()
        if not row:
            return {
                "discord_user_id": discord_user_id,
                "memory_mode": self.DEFAULT_MEMORY_MODE.value,
                "preferred_response_style": "",
                "trusted_tools": [],
                "denied_tools": [],
                "recurring_patterns": [],
                "channel_sensitivity": {},
                "requires_approval": False,
                "frequent_doc_sources": [],
            }
        return {
            "discord_user_id": row["discord_user_id"],
            "memory_mode": row["memory_mode"],
            "preferred_response_style": row["preferred_response_style"],
            "trusted_tools": json.loads(row["trusted_tools"]),
            "denied_tools": json.loads(row["denied_tools"]),
            "recurring_patterns": json.loads(row["recurring_patterns"]),
            "channel_sensitivity": json.loads(row["channel_sensitivity"]),
            "requires_approval": bool(row["requires_approval"]),
            "frequent_doc_sources": json.loads(row["frequent_doc_sources"]),
        }

    def store_user_memory(self, discord_user_id: str, data: dict) -> None:
        with self._db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO user_memory "
                "(discord_user_id, memory_mode, preferred_response_style, "
                "trusted_tools, denied_tools, recurring_patterns, "
                "channel_sensitivity, requires_approval, "
                "frequent_doc_sources, last_updated) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    discord_user_id,
                    data.get("memory_mode", self.DEFAULT_MEMORY_MODE.value),
                    data.get("preferred_response_style", ""),
                    json.dumps(data.get("trusted_tools", [])),
                    json.dumps(data.get("denied_tools", [])),
                    json.dumps(data.get("recurring_patterns", [])),
                    json.dumps(data.get("channel_sensitivity", {})),
                    int(data.get("requires_approval", False)),
                    json.dumps(data.get("frequent_doc_sources", [])),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()

    def determine_memory_mode(self, discord_user_id: str) -> MemoryMode:
        mem = self.load_user_memory(discord_user_id)
        try:
            return MemoryMode(mem.get("memory_mode", "auto"))
        except ValueError:
            return self.DEFAULT_MEMORY_MODE

    # ── Backboard messaging ───────────────────────────────────────────────

    async def send_message_to_backboard(
        self, thread_id: str, content: str, memory_mode: MemoryMode,
    ) -> dict:
        headers = {"X-API-Key": self._api_key}
        async with httpx.AsyncClient(timeout=120) as c:
            resp = await c.post(
                f"{self._base_url}/threads/{thread_id}/messages",
                headers=headers,
                data={
                    "content": content,
                    "stream": "false",
                    "send_to_llm": "true",
                    "memory": memory_mode.to_backboard_param(),
                },
            )
            resp.raise_for_status()
            return resp.json()

    # ── Tool call handling ────────────────────────────────────────────────

    def handle_backboard_tool_calls(self, response_data: dict) -> list[dict]:
        """Parse tool calls from Backboard response (OpenAI Assistants format)."""
        calls: list[dict] = []

        for tc in (response_data.get("tool_calls") or []):
            fn = tc.get("function", {})
            name = fn.get("name", tc.get("name", ""))
            raw_args = fn.get("arguments", tc.get("arguments", "{}"))
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            calls.append({
                "id": tc.get("id", uuid.uuid4().hex[:8]),
                "name": name,
                "arguments": args,
            })

        ra = response_data.get("required_action") or {}
        for tc in (ra.get("submit_tool_outputs") or {}).get("tool_calls") or []:
            fn = tc.get("function", {})
            raw_args = fn.get("arguments", "{}")
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            calls.append({
                "id": tc.get("id", uuid.uuid4().hex[:8]),
                "name": fn.get("name", ""),
                "arguments": args,
            })

        return calls

    async def execute_clawdbot_task(
        self, tool_name: str, tool_args: dict,
    ) -> dict:
        if tool_name not in self.ALLOWED_TOOLS:
            logger.warning(
                "[BackboardInterpreter] Blocked tool %s (not in allowlist)",
                tool_name,
            )
            return {"error": f"Tool '{tool_name}' is not allowed", "status": "blocked"}

        if not isinstance(tool_args, dict):
            return {"error": "Invalid tool arguments", "status": "error"}

        logger.info("[BackboardInterpreter] Executing tool %s", tool_name)

        try:
            messages = tool_args.get("messages", [])
            if not messages and "task" in tool_args:
                messages = [{"role": "user", "content": tool_args["task"]}]
            if not messages:
                messages = [{"role": "user", "content": json.dumps(tool_args)}]

            async with httpx.AsyncClient(timeout=float(self.TOOL_TIMEOUT)) as c:
                resp = await c.post(
                    f"{OPENCLAW_UPSTREAM}/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {OPENCLAW_TOKEN}",
                        "Content-Type": "application/json",
                    },
                    json={"messages": messages},
                )
                resp.raise_for_status()
                data = resp.json()
                content = (
                    data.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                )
                return {"result": content, "status": "success"}

        except httpx.TimeoutException:
            logger.error("[BackboardInterpreter] Tool %s timed out", tool_name)
            return {"error": "Execution timed out", "status": "timeout"}
        except Exception as exc:
            logger.error(
                "[BackboardInterpreter] Tool %s failed: %s", tool_name, exc,
            )
            return {"error": "Execution failed", "status": "error"}

    async def submit_tool_output_to_backboard(
        self, thread_id: str, run_id: str, tool_outputs: list[dict],
    ) -> dict:
        headers = {"X-API-Key": self._api_key}
        async with httpx.AsyncClient(timeout=60) as c:
            if run_id:
                resp = await c.post(
                    f"{self._base_url}/threads/{thread_id}/runs/"
                    f"{run_id}/submit_tool_outputs",
                    headers={**headers, "Content-Type": "application/json"},
                    json={"tool_outputs": tool_outputs},
                )
                if resp.is_success:
                    return resp.json()

            # Fallback: send results as a follow-up message
            parts = [
                f"[Tool {to['tool_call_id']}]\n{to.get('output', '')}"
                for to in tool_outputs
            ]
            resp = await c.post(
                f"{self._base_url}/threads/{thread_id}/messages",
                headers=headers,
                data={
                    "content": "\n\n".join(parts),
                    "stream": "false",
                    "send_to_llm": "true",
                    "memory": "Auto",
                },
            )
            resp.raise_for_status()
            return resp.json()

    # ── Memory update heuristics ──────────────────────────────────────────

    def _maybe_update_memory(
        self, discord_user_id: str, user_message: str, response: str,
    ) -> None:
        mem = self.load_user_memory(discord_user_id)
        lower = user_message.lower()
        updated = False

        style_keywords = (
            "concise", "verbose", "detailed", "brief", "formal", "casual",
        )
        if any(kw in lower for kw in ("be more", "respond in", "use a", "switch to")):
            for style in style_keywords:
                if style in lower:
                    mem["preferred_response_style"] = style
                    updated = True
                    break

        if "always approve" in lower or "skip approval" in lower:
            mem["requires_approval"] = False
            updated = True
        elif "require approval" in lower or "ask before" in lower:
            mem["requires_approval"] = True
            updated = True

        if updated:
            self.store_user_memory(discord_user_id, mem)
            logger.info(
                "[BackboardInterpreter] Updated memory for user=%s",
                discord_user_id,
            )

    # ── Main entry point ──────────────────────────────────────────────────

    async def process_message(
        self,
        discord_user_id: str,
        discord_channel_id: str,
        guild_id: str,
        user_message: str,
        full_messages: list[dict],
    ) -> str:
        """Process a Discord message through Backboard LTM + Clawdbot/OpenClaw."""
        memory_mode = self.determine_memory_mode(discord_user_id)
        thread_id = await self.get_or_create_thread(
            discord_user_id, discord_channel_id, guild_id,
        )

        # Enrich message with memory context when active
        enriched = user_message
        if memory_mode != MemoryMode.OFF:
            user_mem = self.load_user_memory(discord_user_id)
            ctx: list[str] = []
            if user_mem.get("preferred_response_style"):
                ctx.append(
                    f"User prefers {user_mem['preferred_response_style']} responses."
                )
            if user_mem.get("denied_tools"):
                ctx.append(
                    f"Denied tools: {', '.join(user_mem['denied_tools'])}."
                )
            if user_mem.get("requires_approval"):
                ctx.append("User requires approval before execution.")
            if ctx:
                enriched = "[Memory context: " + " ".join(ctx) + "]\n\n" + user_message

        logger.info(
            "[BackboardInterpreter] user=%s channel=%s mode=%s thread=%s",
            discord_user_id, discord_channel_id, memory_mode.value, thread_id,
        )

        # Send to Backboard
        response_data = await self.send_message_to_backboard(
            thread_id, enriched, memory_mode,
        )

        # Tool-call loop
        iterations = 0
        while iterations < self.MAX_TOOL_ITERATIONS:
            tool_calls = self.handle_backboard_tool_calls(response_data)
            status = response_data.get("status", "").lower()
            if not tool_calls and status != "requires_action":
                break

            iterations += 1
            tool_outputs: list[dict] = []
            for tc in tool_calls:
                result = await self.execute_clawdbot_task(
                    tc["name"], tc["arguments"],
                )
                tool_outputs.append({
                    "tool_call_id": tc["id"],
                    "output": json.dumps(result, default=str),
                })

            run_id = response_data.get("run_id", response_data.get("id", ""))
            response_data = await self.submit_tool_output_to_backboard(
                thread_id, run_id, tool_outputs,
            )

        final_text = (response_data.get("content") or "").strip()

        # Fallback: proxy directly to OpenClaw if Backboard returned nothing
        if not final_text:
            logger.info(
                "[BackboardInterpreter] Empty Backboard response — "
                "falling back to OpenClaw",
            )
            try:
                async with httpx.AsyncClient(timeout=60) as c:
                    resp = await c.post(
                        f"{OPENCLAW_UPSTREAM}/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {OPENCLAW_TOKEN}",
                            "Content-Type": "application/json",
                        },
                        json={"messages": full_messages},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    final_text = (
                        data.get("choices", [{}])[0]
                        .get("message", {})
                        .get("content", "")
                    )
            except Exception as exc:
                logger.error(
                    "[BackboardInterpreter] OpenClaw fallback failed: %s", exc,
                )
                final_text = "I'm having trouble processing that right now."

        # Persist insights when memory is writable
        if memory_mode in (MemoryMode.AUTO, MemoryMode.FORCE):
            try:
                self._maybe_update_memory(
                    discord_user_id, user_message, final_text,
                )
            except Exception:
                pass

        return final_text


backboard_interpreter = BackboardInterpreter()


# --- Backboard LTM Routes ---

async def _proxy_to_openclaw_chat(
    messages: list[dict], identity: dict, token_scopes: set[str],
) -> JSONResponse:
    """Forward a chat completions request to OpenClaw directly."""
    headers = {
        "Authorization": f"Bearer {OPENCLAW_TOKEN}",
        "Content-Type": "application/json",
        "X-Auth0-User": identity["sub"],
        "X-Identity-Type": identity["identity_type"],
    }
    if identity["is_agent"]:
        headers["X-Agent-Id"] = identity.get("agent_id", "")
        headers["X-Agent-Name"] = identity.get("agent_name", "")
        headers["X-Agent-Owner"] = identity.get("owner_sub", "")
    try:
        async with httpx.AsyncClient(timeout=60) as c:
            resp = await c.post(
                f"{OPENCLAW_UPSTREAM}/v1/chat/completions",
                headers=headers,
                json={"messages": messages},
            )
            return JSONResponse(
                content=resp.json(), status_code=resp.status_code,
            )
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="OpenClaw gateway unreachable")


@app.post("/v1/chat/completions")
async def chat_completions_with_ltm(request: Request):
    """Chat completions routed through Backboard Long-Term Memory middleware.

    When X-Discord-* headers are present the request goes through the
    BackboardInterpreter for LTM-enriched processing.  Otherwise it falls
    through to a standard OpenClaw proxy.
    """
    payload = await verify_token(request)
    identity = classify_identity(payload)
    token_scopes = set(payload.get("scope", "").split())

    if identity["is_agent"] and identity.get("revoked"):
        raise HTTPException(
            status_code=403, detail="Agent identity has been revoked",
        )

    body = await request.json()
    messages = body.get("messages", [])

    discord_user_id = request.headers.get("X-Discord-User-Id", "")
    discord_channel_id = request.headers.get("X-Discord-Channel-Id", "")
    guild_id = request.headers.get("X-Discord-Guild-Id", "")

    # Extract the latest user message
    user_message = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            user_message = msg.get("content", "")
            break

    # No Discord context or no user message → standard proxy
    if not discord_user_id or not user_message:
        log_request(
            identity, token_scopes, request.method, "/v1/chat/completions", 200,
        )
        return await _proxy_to_openclaw_chat(messages, identity, token_scopes)

    try:
        response_text = await backboard_interpreter.process_message(
            discord_user_id=discord_user_id,
            discord_channel_id=discord_channel_id,
            guild_id=guild_id,
            user_message=user_message,
            full_messages=messages,
        )
    except Exception as exc:
        logger.error("[BackboardInterpreter] %s", exc)
        log_request(
            identity, token_scopes, request.method, "/v1/chat/completions", 200,
        )
        return await _proxy_to_openclaw_chat(messages, identity, token_scopes)

    log_request(
        identity, token_scopes, request.method, "/v1/chat/completions", 200,
    )
    return JSONResponse(content={
        "choices": [{
            "message": {"role": "assistant", "content": response_text},
            "index": 0,
            "finish_reason": "stop",
        }],
    })


@app.get("/shieldclaw/ltm/memory/{discord_user_id}")
async def ltm_get_memory(discord_user_id: str, request: Request):
    """View a user's LTM memory profile."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    if "gateway:admin" not in token_scopes:
        raise HTTPException(
            status_code=403, detail="Scope 'gateway:admin' required",
        )
    return JSONResponse(
        content=backboard_interpreter.load_user_memory(discord_user_id),
    )


@app.post("/shieldclaw/ltm/memory/{discord_user_id}")
async def ltm_update_memory(discord_user_id: str, request: Request):
    """Update a user's LTM memory profile (partial merge)."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    if "gateway:admin" not in token_scopes:
        raise HTTPException(
            status_code=403, detail="Scope 'gateway:admin' required",
        )
    body = await request.json()
    current = backboard_interpreter.load_user_memory(discord_user_id)
    current.update(body)
    backboard_interpreter.store_user_memory(discord_user_id, current)
    return JSONResponse(content=current)


@app.get("/shieldclaw/ltm/status")
async def ltm_status():
    """No-auth: Backboard LTM middleware status."""
    return JSONResponse(content={
        "enabled": True,
        "db_path": backboard_interpreter._db_path,
        "assistant_id": (
            backboard_interpreter._assistant_id
            or "(created on first use)"
        ),
        "default_memory_mode": backboard_interpreter.DEFAULT_MEMORY_MODE.value,
        "backboard_base_url": backboard_interpreter._base_url,
    })


# --- Proxy ---

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(request: Request, path: str):
    # Verify Auth0 JWT
    payload = await verify_token(request)

    token_scopes = set(payload.get("scope", "").split())
    identity = classify_identity(payload)
    request_path = f"/{path}"

    # Block revoked agents
    if identity["is_agent"] and identity.get("revoked"):
        log_request(identity, token_scopes, request.method, request_path, 403)
        raise HTTPException(status_code=403, detail="Agent identity has been revoked")

    # Check scopes against route
    scope_error = check_scopes(token_scopes, request_path)
    if scope_error:
        log_request(identity, token_scopes, request.method, request_path, 403)
        raise HTTPException(status_code=403, detail=scope_error)

    # --- FGA Policy Check (agents only) ---
    if identity["is_agent"]:
        agent_id = identity.get("agent_id", "unknown")
        body = await request.body()
        try:
            body_dict = json.loads(body) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            body_dict = {}

        fga_payload = {"method": request.method, "path": request_path, "body": body_dict}
        action_type = f"{request.method.lower()}:{request_path.strip('/').split('/')[1] if '/' in request_path.strip('/') else request_path.strip('/')}"

        fga_result = check_fga(agent_id, action_type, fga_payload)
        if not fga_result.allowed:
            log_request(identity, token_scopes, request.method, request_path, 403)
            raise HTTPException(status_code=403, detail=fga_result.reason)

    # --- ShieldBot Evaluation (agents only) ---
    body = await request.body()
    if identity["is_agent"]:
        action_req = build_action_request(identity, request.method, request_path, body, payload)
        trust_tier = scopes_to_trust_tier(token_scopes)

        decision = await asyncio.to_thread(evaluate, action_req, trust_tier)

        # Store decision in Backboard thread for this session
        try:
            session_id = payload.get("sub", "unknown")
            thread = shieldbot_backboard.get_or_create_thread(
                user_id=identity.get("agent_id", "unknown"),
                session_id=session_id,
            )
            shieldbot_backboard.append_thread_event(
                thread_id=thread["thread_id"],
                session_id=session_id,
                event={
                    "event_type": "shieldbot_evaluation",
                    "method": request.method,
                    "path": request_path,
                    "action_type": action_req.action_type,
                    "status": decision.status,
                    "risk_score": decision.risk_score,
                    "reason": decision.reason,
                    "factors": decision.factors,
                    "trust_tier": trust_tier,
                    "agent_id": identity.get("agent_id"),
                    "agent_name": identity.get("agent_name"),
                },
            )
        except Exception:
            pass

        async def _request_human_approval() -> bool:
            """Create a pending approval, wait up to 60s, return True if approved."""
            approval_id = str(uuid.uuid4())[:8].upper()
            event = asyncio.Event()
            _pending_approvals[approval_id] = {
                "event": event,
                "approved": None,
                "request": {
                    "method": request.method,
                    "path": request_path,
                    "action_type": action_req.action_type,
                    "reason": decision.reason,
                    "risk_score": decision.risk_score,
                    "agent_name": identity.get("agent_name", "unknown"),
                },
            }
            logger.info(f"[ShieldBot] Awaiting Discord approval (id={approval_id}, risk={decision.risk_score:.0f})")
            timed_out = False
            try:
                await asyncio.wait_for(event.wait(), timeout=90.0)
                approved = _pending_approvals[approval_id]["approved"]
            except asyncio.TimeoutError:
                timed_out = True
                approved = False
            finally:
                _pending_approvals.pop(approval_id, None)

            if timed_out:
                log_request(identity, token_scopes, request.method, request_path, 403)
                raise HTTPException(
                    status_code=403,
                    detail=f"[ShieldBot] Approval timed out after 90s — request auto-denied (risk={decision.risk_score:.0f})",
                )
            if not approved:
                log_request(identity, token_scopes, request.method, request_path, 403)
                raise HTTPException(
                    status_code=403,
                    detail=f"[ShieldBot] Request denied by admin (risk={decision.risk_score:.0f})",
                )
            logger.info(f"[ShieldBot] Admin approved request {approval_id}")
            return True

        if decision.status == "needs_confirmation":
            if decision.risk_score >= 50:
                await _request_human_approval()
            else:
                logger.info(f"[ShieldBot] needs_confirmation risk={decision.risk_score:.0f} < 50, auto-approving")

        elif decision.status == "blocked":
            logger.warning(f"[ShieldBot] BLOCKED — sending to Discord for approval (reason={decision.reason!r} risk={decision.risk_score})")
            await _request_human_approval()

    # Build upstream headers — set identity for OpenClaw trusted-proxy mode
    upstream_headers = dict(request.headers)
    upstream_headers["X-Auth0-User"] = identity["sub"]
    upstream_headers["X-Auth0-Scopes"] = " ".join(sorted(token_scopes))
    upstream_headers["X-Identity-Type"] = identity["identity_type"]

    if identity["is_agent"]:
        upstream_headers["X-Agent-Id"] = identity.get("agent_id", "")
        upstream_headers["X-Agent-Name"] = identity.get("agent_name", "")
        upstream_headers["X-Agent-Owner"] = identity.get("owner_sub", "")

    # Don't forward the JWT itself to OpenClaw — replace with OpenClaw's expected token
    upstream_headers.pop("authorization", None)
    upstream_headers.pop("host", None)
    upstream_headers["authorization"] = f"Bearer {OPENCLAW_TOKEN}"

    # Proxy to OpenClaw gateway
    upstream_url = f"{OPENCLAW_UPSTREAM}/{path}"

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.request(
            method=request.method,
                url=upstream_url,
                headers=upstream_headers,
            content=body,
                params=request.query_params,
        )
    except httpx.ConnectError:
        log_request(identity, token_scopes, request.method, request_path, 502)
        raise HTTPException(status_code=502, detail="OpenClaw gateway unreachable")

    log_request(identity, token_scopes, request.method, request_path, response.status_code)

    # --- Scrub OpenClaw exec-lock / gateway-restart leaks from chat responses ---
    response_body = response.content
    _EXEC_LEAK_PHRASES = [
        b"gateway restart", b"openclaw gateway", b"exec tool", b"allowlist",
        b"open your terminal", b"run `openclaw", b"security allowlist",
        b"won't unlock", b"will not unlock", b"locked down",
    ]
    if response.status_code == 200 and "chat/completions" in request_path:
        try:
            body_lower = response_body.lower()
            if any(p in body_lower for p in _EXEC_LEAK_PHRASES):
                body_json = json.loads(response_body)
                if "choices" in body_json:
                    for choice in body_json["choices"]:
                        if "message" in choice and "content" in choice["message"]:
                            choice["message"]["content"] = "I'm not able to complete that action right now."
                    response_body = json.dumps(body_json).encode()
        except Exception:
            pass

    # --- Data Isolation: redact sensitive content for agent identities ---
    if identity["is_agent"]:
        _cid = identity.get("agent_client_id", "")
        if DEV_BYPASS and (_cid == _DEV_AGENT["auth0_client_id"] or _cid.startswith("discord-")):
            agent_data_access = set(SENSITIVE_PATTERNS.keys())
        else:
            agent_record = agent_registry.get_by_client_id(_cid)
            agent_data_access = set(agent_record.get("data_access", [])) if agent_record else set()
        response_body = redact_response(response_body, identity, agent_data_access)

    # Forward response back to client
    excluded_headers = {"transfer-encoding", "content-encoding", "content-length"}
    response_headers = {
        k: v for k, v in response.headers.items() if k.lower() not in excluded_headers
    }
    return StreamingResponse(
        iter([response_body]),
        status_code=response.status_code,
        headers=response_headers,
    )


if __name__ == "__main__":
    import threading
    import webbrowser
    import uvicorn

    def _open_dashboards():
        import time as _time
        _time.sleep(1.5)  # wait for uvicorn to bind
        base = f"http://localhost:{SHIELDCLAW_PORT}"
        webbrowser.open(f"{base}/shieldclaw/backboard")
        webbrowser.open(f"{base}/shieldclaw/auth0")

    threading.Thread(target=_open_dashboards, daemon=True).start()

    logger.info(f"ShieldClaw starting on port {SHIELDCLAW_PORT}")
    logger.info(f"Auth0 domain: {AUTH0_DOMAIN}")
    logger.info(f"Proxying to OpenClaw at: {OPENCLAW_UPSTREAM}")
    logger.info(f"Backboard dashboard → http://localhost:{SHIELDCLAW_PORT}/shieldclaw/backboard")
    logger.info(f"Auth0 debug panel  → http://localhost:{SHIELDCLAW_PORT}/shieldclaw/auth0")
    uvicorn.run(app, host="0.0.0.0", port=SHIELDCLAW_PORT, access_log=False)
