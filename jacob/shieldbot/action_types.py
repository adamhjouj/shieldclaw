from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional


@dataclass
class ActionRequest:
    user_id: str
    session_id: str
    action_type: str  # arbitrary — no longer restricted to a fixed set
    payload: dict[str, Any] = field(default_factory=dict)  # any action-specific data
    user_preferences: dict[str, Any] = field(default_factory=dict)
    prior_behavior_summary: Optional[str] = None


@dataclass
class Decision:
    status: Literal["approved", "needs_confirmation", "blocked"]
    reason: str
    risk_score: float
    factors: list[str] = field(default_factory=list)
    thread_id: Optional[str] = None
