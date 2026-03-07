const express = require('express');
const router = express.Router();
const { requestCibaApproval } = require('../auth/ciba-handler');
const { executeAction, abortAction } = require('../auth/action-executor');

const MONITORED_EVENTS = ['file.delete', 'payment.initiate', 'transaction.create'];

function buildBindingMessage(event) {
  switch (event.event_type) {
    case 'file.delete':
      return `ClawdBot wants to delete ${event.filename || 'a file'} — approve?`;
    case 'payment.initiate':
      return `ClawdBot wants to initiate payment of ${event.amount || '(unknown amount)'} — approve?`;
    case 'transaction.create':
      return `ClawdBot wants to create transaction ${event.transaction_id || '(unknown)'} — approve?`;
    default:
      return `ClawdBot wants to perform ${event.event_type} — approve?`;
  }
}

router.post('/webhook', async (req, res) => {
  const secret = process.env.BACKBOARDS_WEBHOOK_SECRET;
  if (secret && req.headers['x-backboards-secret'] !== secret) {
    return res.status(401).json({ error: 'Invalid webhook secret' });
  }

  const event = req.body;

  if (!MONITORED_EVENTS.includes(event.event_type)) {
    return res.status(200).json({ status: 'ignored', event_type: event.event_type });
  }

  const userId = event.user_id || process.env.AUTH0_TEST_USER_ID;
  if (!userId) {
    return res.status(400).json({ error: 'No user_id in payload and AUTH0_TEST_USER_ID not set' });
  }

  const bindingMessage = buildBindingMessage(event);

  console.log(`[backboards-webhook] Intercepted ${event.event_type} for user ${userId}`);
  console.log(`[backboards-webhook] Sending Guardian push: "${bindingMessage}"`);

  let result;
  try {
    result = await requestCibaApproval(userId, bindingMessage);
  } catch (err) {
    console.error('[backboards-webhook] CIBA request failed:', err.message);
    abortAction(event, 'ciba_error');
    return res.status(500).json({ error: 'CIBA request failed', detail: err.message });
  }

  if (result === 'approved') {
    executeAction(event);
  } else {
    abortAction(event, result);
  }

  return res.status(200).json({ status: result });
});

module.exports = router;
