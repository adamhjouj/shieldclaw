const crypto = require('crypto');
const express = require('express');
const router = express.Router();
const { initiateCIBA } = require('../auth/ciba-handler');
const { executeAction, abortAction } = require('../auth/action-executor');

function verifySecret(incoming, expected) {
  if (!expected) return true;
  if (!incoming) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(incoming), Buffer.from(expected));
  } catch {
    return false;
  }
}

const MONITORED_EVENTS = ['file.delete', 'payment.initiate', 'transaction.create', 'file.operation'];

// POST /backboards/webhook
//
// Backup endpoint for when Backboards.io pushes events directly.
// Uses the same CIBA email flow as the ClawdBot interceptor.
//
// Expected payload from Backboards.io:
// {
//   event_type:       string   — one of MONITORED_EVENTS
//   user_id?:         string   — Auth0 sub of the affected user
//   filename?:        string   — for file.delete / file.operation events
//   amount?:          string   — for payment.initiate events
//   recipient?:       string   — for payment.initiate events
//   transaction_id?:  string   — for transaction.create events
//   details?:         string   — human-readable detail (any event)
// }
router.post('/webhook', async (req, res) => {
  if (!verifySecret(req.headers['x-backboards-secret'], process.env.BACKBOARDS_WEBHOOK_SECRET)) {
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

  console.log(`[backboards-webhook] Received ${event.event_type} for user ${userId}`);
  console.log(`[backboards-webhook] Initiating CIBA email approval`);

  let cibaResult;
  try {
    cibaResult = await initiateCIBA({
      event_type: event.event_type,
      payload: event,
      user_id: userId,
    });
  } catch (err) {
    console.error('[backboards-webhook] CIBA failed:', err.message);
    abortAction(event.event_type, event, 'ciba_error');
    return res.status(500).json({ error: 'CIBA request failed', detail: err.message });
  }

  if (cibaResult === 'approved') {
    executeAction(event.event_type, event);
  } else {
    abortAction(event.event_type, event, cibaResult);
  }

  return res.status(200).json({ status: cibaResult });
});

module.exports = router;
