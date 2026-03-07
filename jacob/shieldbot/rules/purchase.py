from __future__ import annotations

from ..types import ActionRequest, Decision
from .. import config


def evaluate_purchase(req: ActionRequest, user_prefs: dict) -> Decision:
    risk = 0.0
    factors: list[str] = []
    amount = req.amount or 0.0
    vendor = (req.vendor or "").lower().strip()
    category = (req.category or "").lower().strip()

    # blocked vendor — immediate block
    if vendor in config.BLOCKED_VENDORS:
        return Decision(
            status="blocked",
            reason=f"Vendor '{req.vendor}' is on the blocked list.",
            risk_score=100.0,
            factors=["blocked_vendor"],
        )

    # amount thresholds
    if amount > config.PURCHASE_HIGH_RISK_LIMIT:
        risk += 60
        factors.append(f"high_amount (${amount:,.2f})")
    elif amount > config.PURCHASE_AUTO_APPROVE_LIMIT:
        risk += 35
        factors.append(f"elevated_amount (${amount:,.2f})")

    # unusual vendor
    if vendor in config.UNUSUAL_VENDORS:
        risk += 20
        factors.append("unusual_vendor")

    # unusual category
    if category in config.UNUSUAL_CATEGORIES:
        risk += 15
        factors.append("unusual_category")

    # user pref: auto-approve disabled
    if not user_prefs.get("purchase_auto_approve", True):
        risk += 10
        factors.append("user_disabled_auto_approve")

    status = _status_from_risk(risk)
    reason = _build_reason(status, amount, factors)
    return Decision(status=status, reason=reason, risk_score=min(risk, 100), factors=factors)


def _status_from_risk(risk: float) -> str:
    if risk >= config.RISK_THRESHOLDS["needs_confirmation"]:
        return "blocked"
    if risk >= config.RISK_THRESHOLDS["approved"]:
        return "needs_confirmation"
    return "approved"


def _build_reason(status: str, amount: float, factors: list[str]) -> str:
    if status == "approved":
        return f"Purchase of ${amount:,.2f} approved — within normal parameters."
    if status == "needs_confirmation":
        return f"Purchase of ${amount:,.2f} requires confirmation: {', '.join(factors)}."
    return f"Purchase of ${amount:,.2f} blocked: {', '.join(factors)}."
