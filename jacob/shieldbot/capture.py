"""OpenClaw request/response capture.

Functions to capture, summarize, and package the input and output of an
OpenClaw interaction so Shieldbot can evaluate and audit it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class OpenClawInput:
    """What the user asked OpenClaw to do."""
    user_request: str
    parsed_action_type: str
    parsed_payload: dict[str, Any] = field(default_factory=dict)
    raw_context: Optional[dict[str, Any]] = None

    def summarize(self) -> str:
        parts = [f"[{self.parsed_action_type}] {self.user_request}"]
        if self.parsed_payload:
            key_fields = {k: v for k, v in self.parsed_payload.items() if v is not None}
            if key_fields:
                parts.append(f"payload: {json.dumps(key_fields, default=str)}")
        return " | ".join(parts)


@dataclass
class OpenClawOutput:
    """What OpenClaw proposed to do (before Shieldbot review)."""
    proposed_action: str
    proposed_details: dict[str, Any] = field(default_factory=dict)
    tool_calls: list[str] = field(default_factory=list)
    raw_response: Optional[str] = None

    def summarize(self) -> str:
        parts = [self.proposed_action]
        if self.tool_calls:
            parts.append(f"tools: {', '.join(self.tool_calls)}")
        if self.proposed_details:
            key_fields = {k: v for k, v in self.proposed_details.items() if v is not None}
            if key_fields:
                parts.append(f"details: {json.dumps(key_fields, default=str)}")
        return " | ".join(parts)


@dataclass
class InteractionRecord:
    """Full record of an OpenClaw interaction reviewed by Shieldbot."""
    openclaw_input: OpenClawInput
    openclaw_output: OpenClawOutput
    shieldbot_decision: str
    shieldbot_reason: str
    risk_score: float
    risk_factors: list[str]
    trace_id: str
    thread_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": {
                "user_request": self.openclaw_input.user_request,
                "action_type": self.openclaw_input.parsed_action_type,
                "payload": self.openclaw_input.parsed_payload,
            },
            "output": {
                "proposed_action": self.openclaw_output.proposed_action,
                "proposed_details": self.openclaw_output.proposed_details,
                "tool_calls": self.openclaw_output.tool_calls,
            },
            "decision": {
                "status": self.shieldbot_decision,
                "reason": self.shieldbot_reason,
                "risk_score": self.risk_score,
                "risk_factors": self.risk_factors,
            },
            "trace_id": self.trace_id,
            "thread_id": self.thread_id,
        }


def capture_openclaw_input(
    user_request: str,
    action_type: str,
    payload: dict[str, Any] | None = None,
    raw_context: dict[str, Any] | None = None,
) -> OpenClawInput:
    return OpenClawInput(
        user_request=user_request,
        parsed_action_type=action_type,
        parsed_payload=payload or {},
        raw_context=raw_context,
    )


def capture_openclaw_output(
    proposed_action: str,
    details: dict[str, Any] | None = None,
    tool_calls: list[str] | None = None,
    raw_response: str | None = None,
) -> OpenClawOutput:
    return OpenClawOutput(
        proposed_action=proposed_action,
        proposed_details=details or {},
        tool_calls=tool_calls or [],
        raw_response=raw_response,
    )
