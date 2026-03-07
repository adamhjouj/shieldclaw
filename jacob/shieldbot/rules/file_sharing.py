from __future__ import annotations

from ..types import ActionRequest, Decision
from .. import config


def evaluate_file_share(req: ActionRequest, user_prefs: dict) -> Decision:
    risk = 0.0
    factors: list[str] = []
    email = (req.recipient_email or "").lower().strip()
    sensitivity = (req.file_sensitivity or "public").lower()

    is_external = not _is_internal_email(email)
    is_sensitive = sensitivity in ("confidential", "restricted")

    # user preference: no external sharing
    if is_external and not user_prefs.get("allow_external_sharing", True):
        return Decision(
            status="blocked",
            reason="User preferences prohibit external file sharing.",
            risk_score=90.0,
            factors=["user_blocked_external_sharing"],
        )

    # external + sensitive = blocked
    if is_external and is_sensitive:
        return Decision(
            status="blocked",
            reason=f"Cannot share {sensitivity} file '{req.file_name}' with external recipient ({email}).",
            risk_score=95.0,
            factors=["external_recipient", f"sensitive_file ({sensitivity})"],
        )

    if is_external:
        risk += 40
        factors.append("external_recipient")

    if is_sensitive:
        risk += 25
        factors.append(f"sensitive_file ({sensitivity})")

    if sensitivity == "internal":
        risk += 10
        factors.append("internal_only_file")

    status = _status_from_risk(risk)
    reason = _build_reason(status, req.file_name, email, factors)
    return Decision(status=status, reason=reason, risk_score=min(risk, 100), factors=factors)


def _is_internal_email(email: str) -> bool:
    if not email or "@" not in email:
        return False
    domain = email.split("@", 1)[1]
    return domain in config.INTERNAL_EMAIL_DOMAINS


def _status_from_risk(risk: float) -> str:
    if risk >= config.RISK_THRESHOLDS["needs_confirmation"]:
        return "blocked"
    if risk >= config.RISK_THRESHOLDS["approved"]:
        return "needs_confirmation"
    return "approved"


def _build_reason(status: str, file_name: str | None, email: str, factors: list[str]) -> str:
    fname = file_name or "file"
    if status == "approved":
        return f"Sharing '{fname}' with {email} approved."
    if status == "needs_confirmation":
        return f"Sharing '{fname}' with {email} requires confirmation: {', '.join(factors)}."
    return f"Sharing '{fname}' with {email} blocked: {', '.join(factors)}."
