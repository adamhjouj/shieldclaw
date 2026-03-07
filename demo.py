#!/usr/bin/env python3
"""
ShieldClaw demo — runs the full flow in code:
1. Get admin token from Auth0
2. Hit /whoami to show identity
3. Register an agent with a natural language policy
4. Get a token for that agent
5. Hit /identity-report to show security layers
6. Revoke the agent
"""

import asyncio
import json
import os
from dotenv import load_dotenv
import httpx

load_dotenv()

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "codcodingcode.ca.auth0.com")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "https://shieldclaw-gateway")
CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
SHIELDCLAW = "http://localhost:8443"


def pretty(data: dict):
    print(json.dumps(data, indent=2))


async def get_token(client_id: str, client_secret: str) -> str:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "audience": AUTH0_AUDIENCE,
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


async def main():
    print("=" * 60)
    print("ShieldClaw Demo")
    print("=" * 60)

    # 1. Get admin token
    print("\n[1] Getting admin token from Auth0...")
    token = await get_token(CLIENT_ID, CLIENT_SECRET)
    print(f"    Got token: {token[:40]}...")

    headers = {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient(base_url=SHIELDCLAW) as sc:

        # 2. Whoami
        print("\n[2] Who am I?")
        resp = await sc.get("/shieldclaw/whoami", headers=headers)
        pretty(resp.json())

        # 3. Register an agent
        print("\n[3] Registering agent 'demo-bot' with natural language policy...")
        resp = await sc.post(
            "/shieldclaw/agents",
            headers=headers,
            json={
                "agent_name": "demo-bot",
                "policy": "read-only access, can send messages, no access to PII or financial data",
            },
        )
        resp.raise_for_status()
        agent = resp.json()
        pretty(agent)

        agent_id = agent["agent_id"]
        agent_client_id = agent["client_id"]
        agent_client_secret = agent["client_secret"]

        # 4. Get a token for the agent
        print(f"\n[4] Getting token for agent '{agent['agent_name']}'...")
        agent_token = await get_token(agent_client_id, agent_client_secret)
        print(f"    Got agent token: {agent_token[:40]}...")

        agent_headers = {"Authorization": f"Bearer {agent_token}"}

        # 5. Identity report for the agent
        print("\n[5] Agent identity-report (shows security layers + isolation)...")
        resp = await sc.get("/shieldclaw/identity-report", headers=agent_headers)
        pretty(resp.json())

        # 6. Revoke the agent
        print(f"\n[6] Revoking agent {agent_id}...")
        resp = await sc.post(f"/shieldclaw/agents/{agent_id}/revoke", headers=headers)
        pretty(resp.json())

        # 7. Try to use revoked agent token
        print("\n[7] Trying to use revoked agent token (should get 403)...")
        resp = await sc.get("/shieldclaw/whoami", headers=agent_headers)
        print(f"    Status: {resp.status_code}")
        pretty(resp.json())

    print("\n" + "=" * 60)
    print("Demo complete.")


if __name__ == "__main__":
    asyncio.run(main())
