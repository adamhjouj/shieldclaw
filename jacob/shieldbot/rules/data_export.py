from __future__ import annotations

from ..types import ActionRequest, Decision
from .. import config


def evaluate_data_export(req: ActionRequest, user_prefs: dict) -> Decision:
    risk = 0.0
    factors: list[str] = []
    scope = (req.export_scope or "").lower().strip()
    row_count = req.export_row_count or 0
    contains_sensitive = req.export_contains_sensitive_data

    # full database export — very high risk
    if scope in ("full", "full_database", "all"):
        risk += 70
        factors.append("full_database_export")

    # sensitive data
    if contains_sensitive:
        risk += 40
        factors.append("contains_sensitive_data")

    # row count thresholds
    if row_count > config.EXPORT_LARGE_ROW_LIMIT:
        risk += 30
        factors.append(f"large_export ({row_count:,} rows)")
    elif row_count > config.EXPORT_SMALL_ROW_LIMIT:
        risk += 15
        factors.append(f"medium_export ({row_count:,} rows)")

    # user pref: exports disabled
    if not user_prefs.get("export_allowed", True):
        risk += 20
        factors.append("user_disabled_exports")

    status = _status_from_risk(risk)
    reason = _build_reason(status, scope, row_count, factors)
    return Decision(status=status, reason=reason, risk_score=min(risk, 100), factors=factors)


def _status_from_risk(risk: float) -> str:
    if risk >= config.RISK_THRESHOLDS["needs_confirmation"]:
        return "blocked"
    if risk >= config.RISK_THRESHOLDS["approved"]:
        return "needs_confirmation"
    return "approved"


def _build_reason(status: str, scope: str, row_count: int, factors: list[str]) -> str:
    desc = f"'{scope}' export" if scope else "data export"
    if row_count:
        desc += f" ({row_count:,} rows)"
    if status == "approved":
        return f"Data export approved: {desc}."
    if status == "needs_confirmation":
        return f"Data export requires confirmation: {desc} — {', '.join(factors)}."
    return f"Data export blocked: {desc} — {', '.join(factors)}."
