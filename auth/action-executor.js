// executeAction and abortAction are only called after a CIBA decision.
// Default is ALWAYS abort — executeAction is only reachable on explicit 'approved'.

function executeAction(event_type, payload = {}) {
  console.log(
    `[action-executor] CIBA APPROVED — executing ${event_type} for user ${payload.user_id || '(unknown)'}`,
    payload
  );
  // TODO: wire in real action dispatch per event_type
}

function abortAction(event_type, payload = {}, reason) {
  console.warn(
    `[action-executor] CIBA BLOCKED — ${event_type} ${reason} for user ${payload.user_id || '(unknown)'}. No action taken.`,
    payload
  );
}

module.exports = { executeAction, abortAction };
