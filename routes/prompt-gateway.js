const crypto = require('crypto');
const express = require('express');
const router = express.Router();
const { scanPrompt } = require('../auth/prompt-scanner');
const { requestCibaApproval } = require('../auth/ciba-handler');
const { executeAction, abortAction } = require('../auth/action-executor');

function verifySecret(incoming, expected) {
  if (!expected) return true; // no secret configured — open
  if (!incoming) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(incoming), Buffer.from(expected));
  } catch {
    return false; // buffers are different lengths → reject
  }
}

const BACKBOARD_BASE_URL = process.env.BACKBOARD_BASE_URL || '';

async function forwardToBackboard(threadId, content, memory = 'Auto') {
  const apiKey = process.env.BACKBOARD_API_KEY;
  if (!apiKey) throw new Error('BACKBOARD_API_KEY is not set');

  const res = await fetch(`${BACKBOARD_BASE_URL}/threads/${threadId}/messages`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({ content, memory, stream: false }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`Backboard API error ${res.status}: ${data.error || data.message || 'unknown'}`);
  }
  return data;
}

function buildBindingMessage(category, content) {
  const excerpt = content.length > 60 ? content.slice(0, 57) + '...' : content;
  if (category === 'deletion') {
    return `ClawdBot wants to delete something: "${excerpt}" — approve?`;
  }
  return `ClawdBot wants to make a payment: "${excerpt}" — approve?`;
}

// POST /backboards/prompt
// Intercepts messages destined for Backboard.io, scans for sensitive keywords,
// and requires CIBA approval before forwarding when triggered.
//
// Body: { thread_id, content, user_id?, memory? }
router.post('/prompt', async (req, res) => {
  if (!verifySecret(req.headers['x-backboards-secret'], process.env.BACKBOARDS_WEBHOOK_SECRET)) {
    return res.status(401).json({ error: 'Invalid webhook secret' });
  }

  // Accept both 'content' (Backboard API naming) and 'prompt' (legacy alias)
  const { thread_id, content, prompt, user_id, memory } = req.body;
  const messageContent = content || prompt;

  if (!messageContent || typeof messageContent !== 'string') {
    return res.status(400).json({ error: 'content (or prompt) is required and must be a string' });
  }
  if (!thread_id) {
    return res.status(400).json({ error: 'thread_id is required to forward to Backboard.io' });
  }

  const scan = scanPrompt(messageContent);

  // Clean prompt — forward directly to Backboard.io without CIBA
  if (!scan.triggered) {
    console.log(`[prompt-gateway] Clean prompt — forwarding to Backboard thread ${thread_id}`);
    try {
      const backboardRes = await forwardToBackboard(thread_id, messageContent, memory);
      return res.status(200).json({ status: 'allowed', backboard: backboardRes });
    } catch (err) {
      console.error('[prompt-gateway] Backboard forward failed:', err.message);
      return res.status(502).json({ error: 'Failed to forward to Backboard.io', detail: err.message });
    }
  }

  // Sensitive prompt — require CIBA approval before forwarding
  const userId = user_id || process.env.AUTH0_TEST_USER_ID;
  if (!userId) {
    return res.status(400).json({ error: 'No user_id in body and AUTH0_TEST_USER_ID not set' });
  }

  const bindingMessage = buildBindingMessage(scan.category, messageContent);
  console.log(`[prompt-gateway] Sensitive prompt (${scan.category}): ${scan.matchedKeywords.join(', ')}`);
  console.log(`[prompt-gateway] Holding Backboard message — Guardian push: "${bindingMessage}"`);

  let cibaResult;
  try {
    cibaResult = await requestCibaApproval(userId, bindingMessage);
  } catch (err) {
    console.error('[prompt-gateway] CIBA request failed:', err.message);
    abortAction({ event_type: `prompt.${scan.category}`, content: messageContent }, 'ciba_error');
    return res.status(500).json({ error: 'CIBA request failed', detail: err.message });
  }

  const event = { event_type: `prompt.${scan.category}`, content: messageContent };

  if (cibaResult !== 'approved') {
    abortAction(event, cibaResult);
    return res.status(200).json({
      status: cibaResult,
      triggered: true,
      matchedKeywords: scan.matchedKeywords,
      category: scan.category,
      backboard: null, // message was NOT forwarded
    });
  }

  // Approved — now forward to Backboard.io
  executeAction(event);
  console.log(`[prompt-gateway] CIBA approved — forwarding to Backboard thread ${thread_id}`);
  try {
    const backboardRes = await forwardToBackboard(thread_id, messageContent, memory);
    return res.status(200).json({
      status: 'approved',
      triggered: true,
      matchedKeywords: scan.matchedKeywords,
      category: scan.category,
      backboard: backboardRes,
    });
  } catch (err) {
    console.error('[prompt-gateway] Backboard forward failed after CIBA approval:', err.message);
    return res.status(502).json({ error: 'CIBA approved but Backboard forward failed', detail: err.message });
  }
});

module.exports = router;
