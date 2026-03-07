"""
Agent Identity Management for ShieldClaw.

Manages Auth0 Machine-to-Machine (M2M) application registrations for AI agents.
Each agent gets its own client_id/client_secret via Auth0's Management API,
so it operates under a distinct identity rather than the developer's personal credentials.
"""

import json
import time
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict

import httpx

from vault import vault

logger = logging.getLogger("shieldclaw.agent_identity")

AUTH0_DOMAIN = vault.get("AUTH0_DOMAIN", "codcodingcode.ca.auth0.com")
AUTH0_MGMT_CLIENT_ID = vault.get("AUTH0_MGMT_CLIENT_ID")
AUTH0_MGMT_CLIENT_SECRET = vault.get("AUTH0_MGMT_CLIENT_SECRET")
AUTH0_AUDIENCE = vault.get("AUTH0_AUDIENCE", "https://shieldclaw-gateway")

AGENT_REGISTRY_PATH = Path("agent_registry.json")


@dataclass
class AgentRegistration:
    agent_id: str
    agent_name: str
    auth0_client_id: str
    owner_sub: str  # Auth0 sub of the developer who registered this agent
    scopes: list[str]
    created_at: float
    revoked: bool = False
    data_access: list[str] = None  # which sensitive data categories this agent can see

    def __post_init__(self):
        if self.data_access is None:
            self.data_access = []  # default: agent sees no sensitive data


class AgentRegistry:
    """Local registry that maps agent identities to their Auth0 M2M app credentials."""

    def __init__(self, path: Path = AGENT_REGISTRY_PATH):
        self.path = path
        self._agents: dict[str, dict] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            self._agents = json.loads(self.path.read_text())
        else:
            self._agents = {}

    def _save(self):
        self.path.write_text(json.dumps(self._agents, indent=2))

    def register(self, reg: AgentRegistration):
        self._agents[reg.agent_id] = asdict(reg)
        self._save()

    def get(self, agent_id: str) -> Optional[dict]:
        return self._agents.get(agent_id)

    def get_by_client_id(self, client_id: str) -> Optional[dict]:
        for agent in self._agents.values():
            if agent["auth0_client_id"] == client_id:
                return agent
        return None

    def revoke(self, agent_id: str) -> bool:
        if agent_id in self._agents:
            self._agents[agent_id]["revoked"] = True
            self._save()
            return True
        return False

    def list_agents(self, owner_sub: Optional[str] = None) -> list[dict]:
        agents = list(self._agents.values())
        if owner_sub:
            agents = [a for a in agents if a["owner_sub"] == owner_sub]
        return agents


class Auth0ManagementClient:
    """Interact with Auth0 Management API to create/manage M2M applications for agents."""

    def __init__(self):
        self.domain = AUTH0_DOMAIN
        self.client_id = AUTH0_MGMT_CLIENT_ID
        self.client_secret = AUTH0_MGMT_CLIENT_SECRET
        self.audience = AUTH0_AUDIENCE
        self._mgmt_token: Optional[str] = None
        self._mgmt_token_expires: float = 0

    async def _get_mgmt_token(self) -> str:
        """Get a Management API token via client credentials."""
        if self._mgmt_token and time.time() < self._mgmt_token_expires:
            return self._mgmt_token

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://{self.domain}/oauth/token",
                json={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "audience": f"https://{self.domain}/api/v2/",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        self._mgmt_token = data["access_token"]
        self._mgmt_token_expires = time.time() + data.get("expires_in", 3600) - 60
        return self._mgmt_token

    async def create_agent_application(
        self, agent_name: str, description: str, scopes: list[str]
    ) -> dict:
        """Create a new Auth0 M2M application for an AI agent.

        Returns dict with client_id, client_secret.
        """
        token = await self._get_mgmt_token()

        async with httpx.AsyncClient() as client:
            # Create the M2M application
            resp = await client.post(
                f"https://{self.domain}/api/v2/clients",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "name": f"shieldclaw-agent-{agent_name}",
                    "description": description,
                    "app_type": "non_interactive",
                    "grant_types": ["client_credentials"],
                    "client_metadata": {
                        "shieldclaw_agent": "true",
                        "agent_name": agent_name,
                    },
                },
            )
            resp.raise_for_status()
            app_data = resp.json()

            client_id = app_data["client_id"]
            client_secret = app_data["client_secret"]

            # Grant the M2M app access to the ShieldClaw API with specified scopes
            resp = await client.post(
                f"https://{self.domain}/api/v2/client-grants",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "client_id": client_id,
                    "audience": self.audience,
                    "scope": scopes,
                },
            )
            resp.raise_for_status()

        logger.info(f"Created Auth0 M2M app for agent '{agent_name}': client_id={client_id}")
        return {"client_id": client_id, "client_secret": client_secret}

    async def delete_agent_application(self, client_id: str):
        """Delete an Auth0 M2M application (revoke agent permanently)."""
        token = await self._get_mgmt_token()

        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"https://{self.domain}/api/v2/clients/{client_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()

        logger.info(f"Deleted Auth0 M2M app: client_id={client_id}")

    async def rotate_agent_secret(self, client_id: str) -> dict:
        """Rotate the client secret for an agent's M2M application."""
        token = await self._get_mgmt_token()

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://{self.domain}/api/v2/clients/{client_id}/rotate-secret",
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            data = resp.json()

        logger.info(f"Rotated secret for client_id={client_id}")
        return {"client_id": data["client_id"], "client_secret": data["client_secret"]}

    async def update_agent_scopes(self, client_id: str, scopes: list[str]):
        """Update the granted scopes for an agent's M2M application."""
        token = await self._get_mgmt_token()

        async with httpx.AsyncClient() as client:
            # Find the existing client grant
            resp = await client.get(
                f"https://{self.domain}/api/v2/client-grants",
                headers={"Authorization": f"Bearer {token}"},
                params={"client_id": client_id, "audience": self.audience},
            )
            resp.raise_for_status()
            grants = resp.json()

            if not grants:
                raise ValueError(f"No client grant found for client_id={client_id}")

            grant_id = grants[0]["id"]

            resp = await client.patch(
                f"https://{self.domain}/api/v2/client-grants/{grant_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"scope": scopes},
            )
            resp.raise_for_status()

        logger.info(f"Updated scopes for client_id={client_id}: {scopes}")
