"""Central evaluation pipeline.

Takes an ActionRequest, runs it through the appropriate rule set,
manages thread context & memory, logs the decision, and returns a Decision.
"""

from __future__ import annotations

from .types import ActionRequest, Decision
from .rules import evaluate_purchase, evaluate_file_share, evaluate_data_export
from . import thread_manager, memory, logger


_EVALUATORS = {
    "purchase": evaluate_purchase,
    "file_share": evaluate_file_share,
    "data_export": evaluate_data_export,
}


def evaluate(request: ActionRequest) -> Decision:
    # 1. Thread context
    thread = thread_manager.get_or_create_thread(request.session_id, request.user_id)
    thread_id = thread["thread_id"]

    # 2. User memory & preferences
    user_mem = memory.get_user_memory(request.user_id)
    prefs = {**user_mem["preferences"], **request.user_preferences}

    # 3. Run the rule evaluator for this action type
    evaluator_fn = _EVALUATORS.get(request.action_type)
    if evaluator_fn is None:
        decision = Decision(
            status="blocked",
            reason=f"Unknown action type: '{request.action_type}'.",
            risk_score=100.0,
            factors=["unknown_action_type"],
            thread_id=thread_id,
        )
    else:
        decision = evaluator_fn(request, prefs)
        decision.thread_id = thread_id

    # 4. Log the decision to the audit trail
    log_entry = logger.log_decision(request, decision)

    # 5. Update thread history
    thread_manager.append_to_thread(request.session_id, {
        "action_type": request.action_type,
        "status": decision.status,
        "risk_score": decision.risk_score,
    })

    # 6. Update user memory
    memory.update_user_memory(request.user_id, {
        "action_type": request.action_type,
        "status": decision.status,
        "risk_score": decision.risk_score,
        "reason": decision.reason,
    })

    return decision
