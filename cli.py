#!/usr/bin/env python3
"""
ShieldClaw CLI — Manage AI agent identities.

Usage:
    python cli.py register --name "claude-code-dev" --scopes gateway:read,gateway:message,gateway:tools
    python cli.py list
    python cli.py revoke --agent-id agent_abc123
    python cli.py rotate-secret --agent-id agent_abc123
    python cli.py whoami --token <JWT>
    python cli.py get-agent-token --client-id <id> --client-secret <secret>
"""

import argparse
import asyncio
import json
import sys

import httpx

SHIELDCLAW_URL = "http://localhost:8443"
AUTH0_DOMAIN = "codcodingcode.ca.auth0.com"
AUTH0_AUDIENCE = "https://shieldclaw-gateway"


def get_token_from_args(args) -> str:
    """Get the admin token from --token arg."""
    token = getattr(args, "token", None)
    if not token:
        print("Error: Provide --token or set SHIELDCLAW_ADMIN_TOKEN env var", file=sys.stderr)
        sys.exit(1)
    return token


async def cmd_register(args):
    token = get_token_from_args(args)

    payload = {
        "agent_name": args.name,
        "description": args.description or f"Agent: {args.name}",
    }
    if args.policy:
        payload["policy"] = args.policy
    if args.scopes:
        payload["scopes"] = [s.strip() for s in args.scopes.split(",")]

    if not args.policy and not args.scopes:
        print("Error: provide --policy or --scopes (or both)", file=sys.stderr)
        sys.exit(1)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SHIELDCLAW_URL}/shieldclaw/agents",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )

    if resp.status_code != 200:
        print(f"Error ({resp.status_code}): {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    print("\n=== Agent Registered Successfully ===")
    print(f"  Agent ID:      {data['agent_id']}")
    print(f"  Agent Name:    {data['agent_name']}")
    print(f"  Client ID:     {data['client_id']}")
    print(f"  Client Secret: {data['client_secret']}")
    print(f"  Scopes:        {', '.join(data['scopes'])}")

    if "policy_interpretation" in data:
        interp = data["policy_interpretation"]
        print(f"\n  Policy ({interp['confidence']} confidence): {interp['reasoning']}")
        for w in interp.get("warnings", []):
            print(f"  WARNING: {w}")
        for note in interp.get("override_note", []):
            print(f"  Note: {note}")

    print("\n  IMPORTANT: Save the client_secret now. It cannot be retrieved later.")
    print("\n  To get a token for this agent:")
    print(f"    python cli.py get-agent-token --client-id {data['client_id']} --client-secret <secret>")


async def cmd_list(args):
    token = get_token_from_args(args)

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{SHIELDCLAW_URL}/shieldclaw/agents",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code != 200:
        print(f"Error ({resp.status_code}): {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    agents = data["agents"]

    if not agents:
        print("No agents registered.")
        return

    print(f"\n{'Agent ID':<20} {'Name':<25} {'Scopes':<40} {'Revoked'}")
    print("-" * 95)
    for a in agents:
        scopes_str = ", ".join(a["scopes"])
        revoked = "YES" if a["revoked"] else "no"
        print(f"{a['agent_id']:<20} {a['agent_name']:<25} {scopes_str:<40} {revoked}")


async def cmd_revoke(args):
    token = get_token_from_args(args)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SHIELDCLAW_URL}/shieldclaw/agents/{args.agent_id}/revoke",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code != 200:
        print(f"Error ({resp.status_code}): {resp.text}", file=sys.stderr)
        sys.exit(1)

    print(f"Agent {args.agent_id} has been revoked.")


async def cmd_rotate_secret(args):
    token = get_token_from_args(args)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SHIELDCLAW_URL}/shieldclaw/agents/{args.agent_id}/rotate-secret",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code != 200:
        print(f"Error ({resp.status_code}): {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    print(f"\n=== Secret Rotated for {args.agent_id} ===")
    print(f"  Client ID:     {data['client_id']}")
    print(f"  New Secret:    {data['client_secret']}")
    print("  The old secret is now invalid.")


async def cmd_whoami(args):
    token = get_token_from_args(args)

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{SHIELDCLAW_URL}/shieldclaw/whoami",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code != 200:
        print(f"Error ({resp.status_code}): {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    print(json.dumps(data, indent=2))


async def cmd_get_agent_token(args):
    """Get an access token for an agent using client credentials flow."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": args.client_id,
                "client_secret": args.client_secret,
                "audience": AUTH0_AUDIENCE,
            },
        )

    if resp.status_code != 200:
        print(f"Error ({resp.status_code}): {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    print(f"\n=== Agent Token ===")
    print(f"  Access Token: {data['access_token']}")
    print(f"  Expires In:   {data.get('expires_in', '?')}s")
    print(f"  Token Type:   {data.get('token_type', 'Bearer')}")

    if args.export:
        print(f"\n  export SHIELDCLAW_AGENT_TOKEN=\"{data['access_token']}\"")


def main():
    parser = argparse.ArgumentParser(
        description="ShieldClaw — AI Agent Identity Management"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # register
    p_reg = subparsers.add_parser("register", help="Register a new agent identity")
    p_reg.add_argument("--name", required=True, help="Agent name (e.g. claude-code-dev)")
    p_reg.add_argument("--policy", help='Plain-English policy (e.g. "read only, no sensitive data")')
    p_reg.add_argument("--scopes", default=None,
                       help="Comma-separated scopes; overrides --policy if both provided")
    p_reg.add_argument("--description", help="Agent description")
    p_reg.add_argument("--token", help="Admin JWT (or set SHIELDCLAW_ADMIN_TOKEN)")

    # list
    p_list = subparsers.add_parser("list", help="List registered agents")
    p_list.add_argument("--token", help="JWT (or set SHIELDCLAW_ADMIN_TOKEN)")

    # revoke
    p_revoke = subparsers.add_parser("revoke", help="Revoke an agent")
    p_revoke.add_argument("--agent-id", required=True, help="Agent ID to revoke")
    p_revoke.add_argument("--token", help="JWT (or set SHIELDCLAW_ADMIN_TOKEN)")

    # rotate-secret
    p_rotate = subparsers.add_parser("rotate-secret", help="Rotate an agent's client secret")
    p_rotate.add_argument("--agent-id", required=True, help="Agent ID")
    p_rotate.add_argument("--token", help="JWT (or set SHIELDCLAW_ADMIN_TOKEN)")

    # whoami
    p_who = subparsers.add_parser("whoami", help="Show identity for a token")
    p_who.add_argument("--token", help="JWT to inspect")

    # get-agent-token
    p_tok = subparsers.add_parser("get-agent-token", help="Get a token for an agent (client credentials)")
    p_tok.add_argument("--client-id", required=True, help="Agent's Auth0 client_id")
    p_tok.add_argument("--client-secret", required=True, help="Agent's Auth0 client_secret")
    p_tok.add_argument("--export", action="store_true", help="Print export command for shell")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "register": cmd_register,
        "list": cmd_list,
        "revoke": cmd_revoke,
        "rotate-secret": cmd_rotate_secret,
        "whoami": cmd_whoami,
        "get-agent-token": cmd_get_agent_token,
    }

    asyncio.run(commands[args.command](args))


if __name__ == "__main__":
    main()
