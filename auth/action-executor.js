function executeAction(event) {
  console.log(`[action-executor] APPROVED — executing ${event.event_type}`, event);
  // TODO: wire in real action logic per event_type
}

function abortAction(event, reason) {
  console.warn(
    `[action-executor] ABORTED — ${event.event_type} was ${reason}. No action taken.`,
    event
  );
}

module.exports = { executeAction, abortAction };
