"""
Agent Token Client for ShieldClaw.

Used by AI agents (e.g. Claude Code) to authenticate as themselves using
Auth0 Client Credentials flow. The agent gets a short-lived JWT under its
own identity, completely separate from the developer's personal credentials.

Usage:
    from agent_token_client import AgentTokenClient

    client = AgentTokenClient(
        client_id="agent_client_id_from_registration",
        client_secret="agent_client_secret_from_registration",
    )
    token = await client.get_token()
    # Use token in Authorization: Bearer header to call ShieldClaw
"""

import os
import time
import logging
from typing import Optional

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("shieldclaw.agent_token")

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "")


class AgentTokenClient:
    """Handles the OAuth2 Client Credentials flow for an AI agent's M2M identity."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        domain: str = AUTH0_DOMAIN,
        audience: str = AUTH0_AUDIENCE,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.domain = domain
        self.audience = audience
        self._token: Optional[str] = None
        self._expires_at: float = 0

    @property
    def is_token_valid(self) -> bool:
        return self._token is not None and time.time() < self._expires_at

    async def get_token(self) -> str:
        """Get a valid access token, refreshing if needed."""
        if self.is_token_valid:
            return self._token

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://{self.domain}/oauth/token",
                json={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "audience": self.audience,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        self._token = data["access_token"]
        # Refresh 60s before expiry to avoid edge cases
        self._expires_at = time.time() + data.get("expires_in", 3600) - 60
        logger.info(f"Agent token acquired (client_id={self.client_id}, expires_in={data.get('expires_in')}s)")
        return self._token

    async def get_auth_header(self) -> dict[str, str]:
        """Get a ready-to-use Authorization header."""
        token = await self.get_token()
        return {"Authorization": f"Bearer {token}"}

    def invalidate(self):
        """Force token refresh on next call."""
        self._token = None
        self._expires_at = 0


class AgentHTTPClient:
    """Wraps httpx with automatic agent authentication for calling ShieldClaw."""

    def __init__(
        self,
        token_client: AgentTokenClient,
        shieldclaw_url: str = "http://localhost:8443",
    ):
        self.token_client = token_client
        self.base_url = shieldclaw_url.rstrip("/")

    async def request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Make an authenticated request to ShieldClaw."""
        auth_header = await self.token_client.get_auth_header()
        headers = {**kwargs.pop("headers", {}), **auth_header}

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.request(
                method=method,
                url=f"{self.base_url}{path}",
                headers=headers,
                **kwargs,
            )
        return resp

    async def get(self, path: str, **kwargs) -> httpx.Response:
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs) -> httpx.Response:
        return await self.request("POST", path, **kwargs)

    async def put(self, path: str, **kwargs) -> httpx.Response:
        return await self.request("PUT", path, **kwargs)

    async def delete(self, path: str, **kwargs) -> httpx.Response:
        return await self.request("DELETE", path, **kwargs)
