import time
import uuid
import logging
from typing import Optional

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
from jose import jwt, JWTError

from agent_identity import AgentRegistry, AgentRegistration, Auth0ManagementClient
from data_policy import redact_response, get_data_policy_summary, SENSITIVE_PATTERNS
from policy_parser import parse_policy

# --- Config ---

AUTH0_DOMAIN = "codcodingcode.ca.auth0.com"
AUTH0_CLIENT_ID = "b7FYYgwB9iyUYUNi3FGbYuotKAkegQv9"
AUTH0_AUDIENCE = "https://shieldclaw-gateway"
AUTH0_ALGORITHMS = ["RS256"]
OPENCLAW_UPSTREAM = "http://127.0.0.1:18789"
SHIELDCLAW_PORT = 8443

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


def check_scopes(token_scopes: set[str], request_path: str) -> Optional[str]:
    """Return an error message if the token lacks required scopes for this route."""
    # Admin routes
    for prefix in ADMIN_ROUTE_PREFIXES:
        if request_path.startswith(prefix):
            if "gateway:admin" not in token_scopes:
                return f"Scope 'gateway:admin' required for {request_path}"

    # Exec routes (dangerous)
    for prefix in EXEC_ROUTE_PREFIXES:
        if request_path.startswith(prefix):
            if "gateway:tools:exec" not in token_scopes:
                return f"Scope 'gateway:tools:exec' required for {request_path}"

    # Standard route scopes
    for route_prefix, required_scopes in ROUTE_SCOPES.items():
        if request_path.startswith(route_prefix):
            if not token_scopes & required_scopes:
                return f"One of {required_scopes} required for {request_path}"

    # Read-only routes (probes, status) require at least gateway:read
    if request_path.startswith("/api/v1/") and not token_scopes & {
        "gateway:read", "gateway:message", "gateway:tools",
        "gateway:tools:exec", "gateway:admin",
    }:
        return "At least 'gateway:read' scope required"

    return None


# --- JWT Verification ---

async def verify_token(request: Request) -> dict:
    """Extract, verify, and decode the Auth0 JWT from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")
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
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTClaimsError as e:
        raise HTTPException(status_code=401, detail=f"Invalid claims: {e}")
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token verification failed: {e}")

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

    agent_record = agent_registry.get_by_client_id(
        identity.get("agent_client_id", "")
    )
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
    body = await request.body()
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
        agent_record = agent_registry.get_by_client_id(
            identity.get("agent_client_id", "")
        )
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
    import uvicorn

    logger.info(f"ShieldClaw starting on port {SHIELDCLAW_PORT}")
    logger.info(f"Auth0 domain: {AUTH0_DOMAIN}")
    logger.info(f"Proxying to OpenClaw at: {OPENCLAW_UPSTREAM}")
    uvicorn.run(app, host="0.0.0.0", port=SHIELDCLAW_PORT)
