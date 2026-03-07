"""Shieldbot — Claude-powered security layer for Clawdbot.

Usage:
    from jacob.shieldbot import evaluate, ActionRequest

    decision = evaluate(ActionRequest(
        user_id="u1",
        session_id="s1",
        action_type="purchase",
        payload={"amount": 50.0, "vendor": "Amazon", "item": "USB-C Cable"},
    ))
    print(decision.status)  # "approved"
"""

from .types import ActionRequest, Decision
from .evaluator import evaluate
from . import memory, thread_manager, logger

__all__ = [
    "evaluate",
    "ActionRequest",
    "Decision",
    "memory",
    "thread_manager",
    "logger",
]
