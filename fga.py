"""
FGA — Fine-Grained Authorization for ShieldClaw.

Two-layer authorization:
  Layer 1: Local YAML policy (fga_policy.yaml) — fast, deterministic, offline
  Layer 2: Auth0 FGA (OpenFGA) — relationship-based, fine-grained, remote

Check order:
  1. YAML deny rules — if any match, block immediately (no FGA call needed)
  2. YAML allow rules — if any match, permit (then optionally verify via FGA)
  3. Auth0 FGA check — if configured, check relationship tuples
  4. No match — block (default deny)

The YAML layer handles command/path-level policy (rm -rf, sudo, etc.).
The FGA layer handles relationship-level policy (does this agent own this resource?).
"""

import asyncio
import re
import json
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

import yaml

logger = logging.getLogger("shieldclaw.fga")

FGA_POLICY_PATH = Path("fga_policy.yaml")


@dataclass
class FGAResult:
    allowed: bool
    reason: str
    matched_rule: Optional[str] = None
    rule_type: Optional[str] = None  # "allow" | "deny" | "default-deny" | "fga-allow" | "fga-deny"


def _load_yaml(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


class FGAPolicy:
    """
    Loaded representation of an agent's FGA policy.
    Supports global defaults + per-agent overrides.
    """

    def __init__(self, policy_data: dict):
        self.deny_rules: list[dict] = policy_data.get("deny", [])
        self.allow_rules: list[dict] = policy_data.get("allow", [])
        self.agent: str = policy_data.get("agent", "default")

    def _match_rule(self, rule: dict, action_type: str, payload: dict) -> bool:
        """Return True if this rule matches the given request."""
        matched_any = False

        if "path_prefix" in rule:
            # Extract path from payload — could be in body, or as the action_type target
            path = (
                payload.get("path")
                or payload.get("file")
                or payload.get("directory")
                or payload.get("body", {}).get("path")
                or payload.get("body", {}).get("file")
                or ""
            )
            if isinstance(path, str) and path:
                prefix = rule["path_prefix"].replace("~", str(Path.home()))
                if path.startswith(prefix) or path.startswith(rule["path_prefix"]):
                    matched_any = True
                else:
                    return False  # path present but doesn't match prefix
            else:
                return False  # rule requires a path but none found

        if "command" in rule:
            # Match against action_type or command field in body
            command_targets = [
                action_type,
                payload.get("body", {}).get("command", ""),
                payload.get("body", {}).get("cmd", ""),
                payload.get("body", {}).get("action", ""),
            ]
            pattern = rule["command"].lower()
            matched_command = any(
                pattern in str(t).lower() for t in command_targets if t
            )
            if matched_command:
                matched_any = True
            else:
                return False

        if "method" in rule:
            request_method = payload.get("method", "").upper()
            if rule["method"].upper() == request_method:
                matched_any = True
            else:
                return False

        if "route_prefix" in rule:
            route = payload.get("path", "")
            if route.startswith(rule["route_prefix"]):
                matched_any = True
            else:
                return False

        if "action_type" in rule:
            pattern = rule["action_type"]
            if re.match(pattern, action_type):
                matched_any = True
            else:
                return False

        return matched_any

    def check(self, action_type: str, payload: dict) -> FGAResult:
        """
        Check whether the request is allowed under this policy.

        Returns FGAResult with allowed=True/False and the reason.
        """
        # 1. Check deny rules first — any match blocks immediately
        for rule in self.deny_rules:
            if self._match_rule(rule, action_type, payload):
                reason = rule.get("reason", f"Denied by rule: {rule}")
                logger.info(
                    f"FGA DENY: agent={self.agent} action={action_type} rule={rule} reason={reason}"
                )
                return FGAResult(
                    allowed=False,
                    reason=f"[FGA] {reason}",
                    matched_rule=str(rule),
                    rule_type="deny",
                )

        # 2. Check allow rules — first match permits
        for rule in self.allow_rules:
            if self._match_rule(rule, action_type, payload):
                reason = rule.get("reason", f"Allowed by rule: {rule}")
                logger.debug(
                    f"FGA ALLOW: agent={self.agent} action={action_type} rule={rule}"
                )
                return FGAResult(
                    allowed=True,
                    reason=reason,
                    matched_rule=str(rule),
                    rule_type="allow",
                )

        # 3. Default deny — no rule matched
        logger.info(
            f"FGA DEFAULT-DENY: agent={self.agent} action={action_type} payload_keys={list(payload.keys())}"
        )
        return FGAResult(
            allowed=False,
            reason=f"[FGA] No allow rule matched for action '{action_type}'. Default-deny policy.",
            rule_type="default-deny",
        )


class FGAEngine:
    """
    Loads and caches FGA policies. Supports:
    - Global default policy (fga_policy.yaml)
    - Per-agent policy overrides (fga_policy_{agent_id}.yaml)
    - Auth0 FGA relationship checks (if configured)
    """

    def __init__(self, policy_path: Path = FGA_POLICY_PATH):
        self.policy_path = policy_path
        self._default_policy: Optional[FGAPolicy] = None
        self._agent_policies: dict[str, FGAPolicy] = {}

    def _load_default(self) -> FGAPolicy:
        if self._default_policy is None:
            if self.policy_path.exists():
                data = _load_yaml(self.policy_path)
                self._default_policy = FGAPolicy(data)
                logger.info(f"FGA: Loaded default policy from {self.policy_path}")
            else:
                logger.warning(
                    f"FGA: No policy file found at {self.policy_path}. Using open-allow fallback."
                )
                self._default_policy = FGAPolicy({"agent": "default", "deny": [], "allow": [{"action_type": ".*", "reason": "No policy file — open allow"}]})
        return self._default_policy

    def _load_agent(self, agent_id: str) -> Optional[FGAPolicy]:
        """Load per-agent policy override if it exists."""
        if agent_id in self._agent_policies:
            return self._agent_policies[agent_id]

        agent_path = self.policy_path.parent / f"fga_policy_{agent_id}.yaml"
        if agent_path.exists():
            data = _load_yaml(agent_path)
            policy = FGAPolicy(data)
            self._agent_policies[agent_id] = policy
            logger.info(f"FGA: Loaded per-agent policy for {agent_id}")
            return policy

        return None

    def reload(self):
        """Force reload all policies from disk."""
        self._default_policy = None
        self._agent_policies.clear()
        logger.info("FGA: Policies reloaded")

    def check(self, agent_id: str, action_type: str, payload: dict) -> FGAResult:
        """
        Run the YAML FGA check for a given agent + action.

        Uses per-agent policy if available, falls back to global default.
        """
        policy = self._load_agent(agent_id) or self._load_default()
        return policy.check(action_type, payload)

    async def check_with_openfga(
        self,
        agent_id: str,
        action_type: str,
        payload: dict,
        user_sub: Optional[str] = None,
    ) -> FGAResult:
        """
        Two-layer check: YAML first, then Auth0 FGA for relationship-based decisions.

        The YAML layer handles command/path deny/allow.
        The FGA layer checks if the agent has the right relationship to the resource.
        """
        # Layer 1: YAML policy check
        yaml_result = self.check(agent_id, action_type, payload)

        # If YAML hard-denied, don't bother with FGA
        if not yaml_result.allowed and yaml_result.rule_type == "deny":
            return yaml_result

        # Layer 2: Auth0 FGA relationship check (non-blocking import)
        try:
            from fga_client import check_permission, _fga_available

            if not _fga_available:
                return yaml_result  # FGA not configured — use YAML result only

            # Determine the FGA object and relation from the request
            fga_object_type, fga_object_id, fga_relation = _extract_fga_context(
                action_type, payload
            )

            if not fga_object_type:
                # No FGA-checkable resource found — fall through to YAML result
                return yaml_result

            # Build the FGA user string
            fga_user = f"agent:{agent_id}"

            allowed = await check_permission(
                user=fga_user,
                relation=fga_relation,
                object_type=fga_object_type,
                object_id=fga_object_id,
                fail_open=(yaml_result.allowed),  # if YAML allowed, fail open on FGA error
            )

            if allowed:
                return FGAResult(
                    allowed=True,
                    reason=f"[FGA] Allowed by Auth0 FGA: {fga_user} {fga_relation} {fga_object_type}:{fga_object_id}",
                    rule_type="fga-allow",
                )
            else:
                # FGA denied — but if YAML explicitly allowed, log warning and still allow
                # (YAML allow = deterministic baseline, FGA = additional check)
                if yaml_result.allowed:
                    logger.warning(
                        f"FGA: Auth0 FGA denied but YAML allowed — using YAML result. "
                        f"user={fga_user} relation={fga_relation} object={fga_object_type}:{fga_object_id}"
                    )
                    return yaml_result

                return FGAResult(
                    allowed=False,
                    reason=f"[FGA] Denied by Auth0 FGA: {fga_user} lacks '{fga_relation}' on {fga_object_type}:{fga_object_id}",
                    rule_type="fga-deny",
                )

        except Exception as e:
            logger.error(f"FGA: Auth0 FGA check failed: {e} — falling back to YAML result")
            return yaml_result


def _extract_fga_context(
    action_type: str, payload: dict
) -> tuple[Optional[str], Optional[str], str]:
    """
    Extract FGA object_type, object_id, and relation from the request context.

    Returns (object_type, object_id, relation) or (None, None, "") if not applicable.
    """
    method = payload.get("method", "GET").upper()
    path = payload.get("path", "")

    # Agent management routes
    if path.startswith("/shieldclaw/agents"):
        parts = path.strip("/").split("/")
        if len(parts) >= 3:
            # /shieldclaw/agents/{agent_id}/...
            agent_id = parts[2]
            if "revoke" in path:
                return "agent_reg", agent_id, "can_revoke"
            elif "rotate" in path:
                return "agent_reg", agent_id, "can_rotate"
            else:
                return "agent_reg", agent_id, "viewer"
        # POST /shieldclaw/agents (create) — check gateway admin
        if method == "POST":
            return "gateway", "main", "admin"
        return "gateway", "main", "viewer"

    # Thread routes
    if "/backboard/threads" in path:
        parts = path.strip("/").split("/")
        for i, p in enumerate(parts):
            if p == "threads" and i + 1 < len(parts):
                thread_id = parts[i + 1]
                return "thread", thread_id, "viewer"
        return None, None, ""

    # Memory routes
    if "/ltm/memory" in path:
        parts = path.strip("/").split("/")
        for i, p in enumerate(parts):
            if p == "memory" and i + 1 < len(parts):
                user_id = parts[i + 1]
                if method == "POST":
                    return "memory", user_id, "admin"
                return "memory", user_id, "viewer"
        return None, None, ""

    # Approval routes
    if "/approval/" in path:
        parts = path.strip("/").split("/")
        for i, p in enumerate(parts):
            if p == "approval" and i + 1 < len(parts):
                approval_id = parts[i + 1]
                if "resolve" in path:
                    return "approval", approval_id, "resolver"
                return "approval", approval_id, "viewer"
        return None, None, ""

    # File operations (from body)
    body = payload.get("body", {})
    file_path = body.get("path") or body.get("file") or body.get("directory")
    if file_path:
        # Normalize to a safe FGA object ID
        safe_id = file_path.replace("/", "_").strip("_")[:64]
        if method == "DELETE" or "delete" in action_type.lower():
            return "file", safe_id, "can_delete"
        if method in ("POST", "PUT", "PATCH"):
            return "file", safe_id, "editor"
        return "file", safe_id, "viewer"

    # Email tool actions (from BackboardInterpreter)
    if "email" in action_type.lower() or "email" in path.lower():
        # Determine relation from the action
        if "delete" in action_type.lower():
            return "email", "mailbox", "can_delete"
        elif "send" in action_type.lower():
            return "email", "mailbox", "can_send"
        elif "read" in action_type.lower() or "inbox" in action_type.lower() or "search" in action_type.lower():
            return "email", "mailbox", "can_read"
        return "email", "mailbox", "can_read"

    # Generic gateway access
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return "gateway", "main", "operator"

    return None, None, ""


# Global singleton
fga = FGAEngine()


def check_fga(agent_id: str, action_type: str, payload: dict) -> FGAResult:
    """Convenience function — call this from main.py (synchronous, YAML only)."""
    return fga.check(agent_id, action_type, payload)


async def check_fga_full(
    agent_id: str,
    action_type: str,
    payload: dict,
    user_sub: Optional[str] = None,
) -> FGAResult:
    """Full check: YAML + Auth0 FGA. Call this from async handlers."""
    return await fga.check_with_openfga(agent_id, action_type, payload, user_sub)
