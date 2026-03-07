"""Structured decision trace — safe audit trail for every Shieldbot evaluation.

This is NOT hidden model chain-of-thought. It is a structured reasoning summary
that records what was detected, what rules/preferences matched, and why the
final decision was made.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Optional


@dataclass
class DecisionTrace:
    trace_id: str
    thread_id: str
    user_id: str
    session_id: str
    action_type: str
    input_summary: str
    output_summary: str
    detected_risk_factors: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    matched_preferences: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    final_decision: Literal["approved", "needs_confirmation", "blocked"] = "blocked"
    final_reason: str = ""
    trust_tier: str = "medium"
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "thread_id": self.thread_id,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "action_type": self.action_type,
            "input_summary": self.input_summary,
            "output_summary": self.output_summary,
            "detected_risk_factors": self.detected_risk_factors,
            "matched_rules": self.matched_rules,
            "matched_preferences": self.matched_preferences,
            "risk_score": self.risk_score,
            "final_decision": self.final_decision,
            "final_reason": self.final_reason,
            "trust_tier": self.trust_tier,
            "timestamp": self.timestamp,
        }


def build_decision_trace(
    *,
    thread_id: str,
    user_id: str,
    session_id: str,
    action_type: str,
    input_summary: str,
    output_summary: str,
    risk_factors: list[str],
    risk_score: float,
    decision: str,
    reason: str,
    trust_tier: str = "medium",
    matched_rules: list[str] | None = None,
    matched_preferences: list[str] | None = None,
) -> DecisionTrace:
    return DecisionTrace(
        trace_id=str(uuid.uuid4()),
        thread_id=thread_id,
        user_id=user_id,
        session_id=session_id,
        action_type=action_type,
        input_summary=input_summary,
        output_summary=output_summary,
        detected_risk_factors=risk_factors,
        matched_rules=matched_rules or [],
        matched_preferences=matched_preferences or [],
        risk_score=risk_score,
        final_decision=decision,
        final_reason=reason,
        trust_tier=trust_tier,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
