import os
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

load_dotenv()

OPENCLAW_UPSTREAM = os.getenv("OPENCLAW_UPSTREAM", "http://localhost:3000")
SHIELDCLAW_PORT = int(os.getenv("SHIELDCLAW_PORT", "8000"))

BLOCKED_TOOLS = {"shell_exec", "file_delete"}
SENSITIVE_PATTERNS = ["password", "secret", "api_key", "token", "private_key"]

ROLE_TOOL_PROFILES = {
    "admin": {"toolProfile": "power", "allowedTools": None},
    "developer": {"toolProfile": "messaging", "allowedTools": [
        "file_read", "file_write", "file_list", "grep", "glob",
    ]},
    "viewer": {"toolProfile": "messaging", "allowedTools": ["file_read", "file_list"]},
}


def resolve_role(request: Request) -> str:
    return request.headers.get("x-shieldclaw-role", "viewer")


def check_tool_policy(role: str, tool_name: str) -> bool:
    profile = ROLE_TOOL_PROFILES.get(role, ROLE_TOOL_PROFILES["viewer"])
    allowed = profile.get("allowedTools")
    if allowed is None:
        return True
    return tool_name in allowed


def redact_secrets(text: str) -> str:
    redacted = text
    for pattern in SENSITIVE_PATTERNS:
        idx = 0
        lower = redacted.lower()
        while True:
            pos = lower.find(pattern, idx)
            if pos == -1:
                break
            eq = redacted.find("=", pos)
            colon = redacted.find(":", pos)
            sep = -1
            if eq != -1 and colon != -1:
                sep = min(eq, colon)
            elif eq != -1:
                sep = eq
            elif colon != -1:
                sep = colon
            if sep != -1 and sep - pos < len(pattern) + 5:
                end = sep + 1
                while end < len(redacted) and redacted[end] not in (" ", "\n", "\r", '"', "'", ",", "}"):
                    end += 1
                redacted = redacted[:sep + 1] + "[REDACTED]" + redacted[end:]
                lower = redacted.lower()
            idx = pos + len(pattern)
    return redacted


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http_client = httpx.AsyncClient(base_url=OPENCLAW_UPSTREAM, timeout=120.0)
    print(f"ShieldClaw proxy started → upstream: {OPENCLAW_UPSTREAM}")
    print(f"Listening on port {SHIELDCLAW_PORT}")
    yield
    await app.state.http_client.aclose()


app = FastAPI(title="ShieldClaw", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "shieldclaw"}


@app.get("/policy")
async def get_policy(request: Request):
    role = resolve_role(request)
    profile = ROLE_TOOL_PROFILES.get(role, ROLE_TOOL_PROFILES["viewer"])
    return {"role": role, "profile": profile}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(request: Request, path: str):
    role = resolve_role(request)
    client: httpx.AsyncClient = request.app.state.http_client

    body = await request.body()
    body_text = body.decode("utf-8", errors="replace") if body else ""

    if any(blocked in body_text for blocked in BLOCKED_TOOLS):
        for blocked in BLOCKED_TOOLS:
            if blocked in body_text and not check_tool_policy(role, blocked):
                raise HTTPException(
                    status_code=403,
                    detail=f"Tool '{blocked}' is not allowed for role '{role}'",
                )

    headers = dict(request.headers)
    headers.pop("host", None)
    headers["x-shieldclaw-role"] = role

    try:
        upstream_resp = await client.request(
            method=request.method,
            url=f"/{path}",
            content=body,
            headers=headers,
            params=dict(request.query_params),
        )
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Cannot reach OpenClaw upstream")

    response_text = upstream_resp.text
    filtered_text = redact_secrets(response_text)

    return JSONResponse(
        content={"data": filtered_text} if filtered_text != response_text else None,
        status_code=upstream_resp.status_code,
        headers=dict(upstream_resp.headers),
        media_type=upstream_resp.headers.get("content-type", "application/json"),
    ) if filtered_text != response_text else JSONResponse(
        status_code=upstream_resp.status_code,
        content=upstream_resp.json() if "json" in upstream_resp.headers.get("content-type", "") else {"raw": response_text},
    )


@app.websocket("/ws/{path:path}")
async def ws_proxy(websocket: WebSocket, path: str):
    await websocket.accept()
    role = resolve_role(websocket)

    try:
        async with httpx.AsyncClient() as client:
            async with client.stream("GET", f"{OPENCLAW_UPSTREAM}/ws/{path}") as upstream:
                async for chunk in upstream.aiter_text():
                    filtered = redact_secrets(chunk)
                    await websocket.send_text(filtered)
    except WebSocketDisconnect:
        pass
    except Exception:
        await websocket.close(code=1011)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=SHIELDCLAW_PORT, reload=True)
