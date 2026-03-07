"""
FGA — Fine-Grained Authorization for ShieldClaw.

Hard gate that runs BEFORE any request reaches OpenClaw.
Default-deny: if no rule explicitly allows something, it's blocked.

Policy is loaded from fga_policy.yaml (per-agent or global default).
This is not an LLM prompt — it's a deterministic rule check in the proxy layer.

Check order:
  1. Deny rules — if any match, block immediately
  2. Allow rules — if any match, permit
  3. No match — block (default deny)

Each rule can match on:
  - path_prefix: filesystem/URL paths the agent is trying to touch
  - command: shell commands or action types
  - method: HTTP method (GET, POST, etc.)
  - route_prefix: OpenClaw API route prefix
"""

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
    rule_type: Optional[str] = None  # "allow" | "deny" | "default-deny"


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
                # Fallback: allow everything if no policy file exists
                # This preserves backward compatibility during rollout
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
        Run the FGA check for a given agent + action.

        Uses per-agent policy if available, falls back to global default.
        """
        policy = self._load_agent(agent_id) or self._load_default()
        return policy.check(action_type, payload)


# Global singleton
fga = FGAEngine()


def check_fga(agent_id: str, action_type: str, payload: dict) -> FGAResult:
    """Convenience function — call this from main.py."""
    return fga.check(agent_id, action_type, payload)
