from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional


@dataclass
class ActionRequest:
    user_id: str
    session_id: str
    action_type: Literal["purchase", "file_share", "data_export"]

    # purchase fields
    amount: Optional[float] = None
    vendor: Optional[str] = None
    item: Optional[str] = None
    category: Optional[str] = None

    # file sharing fields
    recipient_email: Optional[str] = None
    file_name: Optional[str] = None
    file_sensitivity: Literal["public", "internal", "confidential", "restricted"] = "public"

    # data export fields
    export_scope: Optional[str] = None
    export_contains_sensitive_data: bool = False
    export_row_count: Optional[int] = None

    # context
    user_preferences: dict = field(default_factory=dict)
    prior_behavior_summary: Optional[str] = None


@dataclass
class Decision:
    status: Literal["approved", "needs_confirmation", "blocked"]
    reason: str
    risk_score: float
    factors: list[str] = field(default_factory=list)
    thread_id: Optional[str] = None
