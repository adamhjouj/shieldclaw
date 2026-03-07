"""Shieldbot — Claude-powered security layer for Clawdbot/OpenClaw.

Evaluates actions before execution, captures OpenClaw input/output,
and stores structured decision traces via Backboard-style threads and memory.

Quick usage:
    from jacob.shieldbot import evaluate_shieldbot_request

    decision, trace, record = evaluate_shieldbot_request(
        user_request="Buy a USB-C cable on Amazon",
        action_type="purchase",
        payload={"amount": 15.99, "vendor": "Amazon"},
        proposed_action="Execute purchase via Amazon API",
        user_id="alice",
        session_id="s1",
    )
    print(decision.status, trace.final_reason)
"""

from .action_types import ActionRequest, Decision
from .evaluator import evaluate, evaluate_shieldbot_request, record_openclaw_interaction
from .trace import DecisionTrace, build_decision_trace
from .capture import (
    OpenClawInput,
    OpenClawOutput,
    InteractionRecord,
    capture_openclaw_input,
    capture_openclaw_output,
)
from . import backboard, memory, thread_manager, logger

__all__ = [
    # top-level orchestration
    "evaluate_shieldbot_request",
    "record_openclaw_interaction",
    # core evaluate
    "evaluate",
    # types
    "ActionRequest",
    "Decision",
    "DecisionTrace",
    "InteractionRecord",
    "OpenClawInput",
    "OpenClawOutput",
    # builders
    "build_decision_trace",
    "capture_openclaw_input",
    "capture_openclaw_output",
    # subsystems
    "backboard",
    "memory",
    "thread_manager",
    "logger",
]
