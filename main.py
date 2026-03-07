import asyncio
import json
import os
import sys
import time
import uuid
import logging
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
AUTH0_AUDIENCE = vault.get("AUTH0_AUDIENCE", "https://shieldclaw-gateway")
AUTH0_ALGORITHMS = ["RS256"]
OPENCLAW_UPSTREAM = vault.get("OPENCLAW_UPSTREAM", "http://127.0.0.1:18789")
SHIELDCLAW_PORT = int(vault.get("SHIELDCLAW_PORT", "8443"))

JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
ISSUER = f"https://{AUTH0_DOMAIN}/"

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

    return ActionRequest(
        user_id=user_id,
        session_id=session_id,
        action_type=action_type,
        payload={"method": method, "path": path, "body": body_dict},
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
    if DEV_BYPASS and auth_header == f"Bearer {_DEV_TOKEN}":
        scopes = " ".join(_DEV_AGENT["scopes"])
        return {
            "sub": f"{_DEV_AGENT['auth0_client_id']}@clients",
            "gty": "client-credentials",
            "azp": _DEV_AGENT["auth0_client_id"],
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
        if DEV_BYPASS and client_id == _DEV_AGENT["auth0_client_id"]:
            _DEV_AGENT["data_access"] = list(SENSITIVE_PATTERNS.keys())
            identity["agent_id"] = _DEV_AGENT["agent_id"]
            identity["agent_name"] = _DEV_AGENT["agent_name"]
            identity["owner_sub"] = _DEV_AGENT["owner_sub"]
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
    if DEV_BYPASS and _client_id == _DEV_AGENT["auth0_client_id"]:
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
async def backboard_log(request: Request):
    """Return the Backboard audit log as JSON. Requires gateway:admin scope."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    if "gateway:admin" not in token_scopes:
        raise HTTPException(status_code=403, detail="Scope 'gateway:admin' required")
    return JSONResponse(content={"log": shieldbot_logger.get_audit_log()})


@app.get("/shieldclaw/backboard/config")
async def backboard_get_config(request: Request):
    """Return current Shieldbot runtime config. Requires gateway:admin scope."""
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    if "gateway:admin" not in token_scopes:
        raise HTTPException(status_code=403, detail="Scope 'gateway:admin' required")
    return JSONResponse(content=shieldbot_config.get_config())


@app.post("/shieldclaw/backboard/config")
async def backboard_set_config(request: Request):
    """Update Shieldbot runtime config. Requires gateway:admin scope.

    Body: { "eval_mode": "think" | "fast" }
    """
    payload = await verify_token(request)
    token_scopes = set(payload.get("scope", "").split())
    if "gateway:admin" not in token_scopes:
        raise HTTPException(status_code=403, detail="Scope 'gateway:admin' required")
    body = await request.json()
    if "eval_mode" in body:
        try:
            shieldbot_config.set_eval_mode(body["eval_mode"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    return JSONResponse(content=shieldbot_config.get_config())


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

        if decision.status in ("blocked", "needs_confirmation"):
            log_request(identity, token_scopes, request.method, request_path, 403)
            raise HTTPException(
                status_code=403,
                detail=f"[ShieldBot] {decision.reason} (risk={decision.risk_score:.0f}, factors={decision.factors})",
            )

    # Build upstream headers — set identity for OpenClaw trusted-proxy mode
    upstream_headers = dict(request.headers)
    upstream_headers["X-Auth0-User"] = identity["sub"]
    upstream_headers["X-Auth0-Scopes"] = " ".join(sorted(token_scopes))
    upstream_headers["X-Identity-Type"] = identity["identity_type"]

    if identity["is_agent"]:
        upstream_headers["X-Agent-Id"] = identity.get("agent_id", "")
        upstream_headers["X-Agent-Name"] = identity.get("agent_name", "")
        upstream_headers["X-Agent-Owner"] = identity.get("owner_sub", "")

    # Don't forward the JWT itself to OpenClaw
    upstream_headers.pop("authorization", None)
    upstream_headers.pop("host", None)

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

    # --- Data Isolation: redact sensitive content for agent identities ---
    response_body = response.content
    if identity["is_agent"]:
        _cid = identity.get("agent_client_id", "")
        if DEV_BYPASS and _cid == _DEV_AGENT["auth0_client_id"]:
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
    uvicorn.run(app, host="0.0.0.0", port=SHIELDCLAW_PORT)
