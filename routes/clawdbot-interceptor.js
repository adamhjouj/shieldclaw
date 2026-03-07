const crypto = require('crypto');
const express = require('express');
const router = express.Router();
const { scanForSensitiveContent } = require('../services/backboards-scanner');
const { initiateCIBA } = require('../auth/ciba-handler');
const { executeAction, abortAction } = require('../auth/action-executor');

function verifySecret(incoming, expected) {
  if (!expected) return true; // no secret configured — open
  if (!incoming) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(incoming), Buffer.from(expected));
  } catch {
    return false; // different lengths → reject
  }
}

// POST /clawdbot/intercept
//
// Primary interception point for ClawdBot output. Call this before any action
// executes. ClawdBot sends its proposed output here; this route:
//   1. Passes the text through the Backboards.io keyword scanner
//   2. If clean  → returns { status: 'allowed' } immediately
//   3. If sensitive → fires CIBA email to the user and holds execution
//   4. On approve → calls executeAction, returns { status: 'approved' }
//   5. On deny/expire → calls abortAction, returns { status: 'denied'|'expired' }
//
// Body: {
//   text:       string   — ClawdBot's proposed output or action description (required)
//   user_id?:   string   — Auth0 sub for the user to notify (falls back to AUTH0_TEST_USER_ID)
//   thread_id?: string   — Backboard.io thread ID for memory logging (optional)
//   payload?:   object   — Extra context forwarded to action-executor (filename, amount, etc.)
// }
router.post('/intercept', async (req, res) => {
  if (!verifySecret(req.headers['x-backboards-secret'], process.env.BACKBOARDS_WEBHOOK_SECRET)) {
    return res.status(401).json({ error: 'Invalid webhook secret' });
  }

  const { text, user_id, thread_id, payload = {} } = req.body;

  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'text is required and must be a string' });
  }

  // Scan via Backboards.io scanner (logs to Backboard thread if thread_id provided)
  let scan;
  try {
    scan = await scanForSensitiveContent(text, { threadId: thread_id });
  } catch (err) {
    console.error('[clawdbot-interceptor] Scanner error:', err.message);
    return res.status(500).json({ error: 'Scan failed', detail: err.message });
  }

  // ── Clean — let ClawdBot proceed ─────────────────────────────────────────
  if (!scan.isSensitive) {
    console.log('[clawdbot-interceptor] Clean output — proceeding normally');
    return res.status(200).json({ status: 'allowed', text });
  }

  // ── Sensitive — hold execution, require CIBA approval ────────────────────
  const userId = user_id || process.env.AUTH0_TEST_USER_ID;
  if (!userId) {
    return res.status(400).json({
      error: 'Sensitive content detected but no user_id provided. Set AUTH0_TEST_USER_ID or pass user_id in the request body.',
    });
  }

  console.log(`[clawdbot-interceptor] Sensitive output (${scan.event_type}): ${scan.keywords_found.join(', ')}`);
  console.log(`[clawdbot-interceptor] Holding execution — CIBA email sent to user ${userId}`);

  let cibaResult;
  try {
    cibaResult = await initiateCIBA({
      event_type: scan.event_type,
      payload: { ...payload, user_id: userId },
      user_id: userId,
    });
  } catch (err) {
    console.error('[clawdbot-interceptor] CIBA initiation failed:', err.message);
    abortAction(scan.event_type, { ...payload, user_id: userId }, 'ciba_error');
    return res.status(500).json({ error: 'CIBA request failed', detail: err.message });
  }

  const fullPayload = { ...payload, user_id: userId, keywords_found: scan.keywords_found };

  if (cibaResult === 'approved') {
    executeAction(scan.event_type, fullPayload);
    return res.status(200).json({
      status: 'approved',
      event_type: scan.event_type,
      keywords_found: scan.keywords_found,
    });
  }

  // denied or expired — always abort, never proceed
  abortAction(scan.event_type, fullPayload, cibaResult);
  return res.status(200).json({
    status: cibaResult,
    event_type: scan.event_type,
    keywords_found: scan.keywords_found,
  });
});

module.exports = router;
