// Validate required env vars at startup — fail immediately with a clear message.
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;

if (!AUTH0_DOMAIN || !CLIENT_ID || !CLIENT_SECRET) {
  throw new Error(
    '[ciba-handler] Missing required env vars: AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET must all be set.'
  );
}

const MAX_WAIT_MS = 120 * 1000;       // hard ceiling on total approval wait
const MAX_POLL_INTERVAL_MS = 60000;   // cap slow_down backoff at 60 s

// ── Binding message builders ─────────────────────────────────────────────────

function buildBindingMessage(event_type, payload) {
  switch (true) {
    case event_type === 'file.delete':
      return `ClawdBot file delete: approve or deny via email`;
    case event_type === 'file.operation':
      return `ClawdBot file operation: approve or deny via email`;
    case event_type.startsWith('payment.'):
      return `ClawdBot payment action: approve or deny via email`;
    case event_type.startsWith('transaction.'):
      return `ClawdBot transaction: approve or deny via email`;
    default:
      return `ClawdBot sensitive action: approve or deny via email`;
  }
}

// ── Auth0 helpers ────────────────────────────────────────────────────────────

async function safeJson(res) {
  try {
    return await res.json();
  } catch {
    const text = await res.text().catch(() => '(unreadable)');
    throw new Error(`Auth0 returned non-JSON response (${res.status}): ${text.slice(0, 200)}`);
  }
}

async function bcAuthorize(userId, bindingMessage) {
  const loginHint = JSON.stringify({
    format: 'iss_sub',
    iss: `https://${AUTH0_DOMAIN}/`,
    sub: userId,
  });

  const body = new URLSearchParams({
    client_id:       CLIENT_ID,
    client_secret:   CLIENT_SECRET,
    scope:           'openid email',   // email channel
    login_hint:      loginHint,
    binding_message: bindingMessage,
    request_expiry:  '120',
  });

  const res = await fetch(`https://${AUTH0_DOMAIN}/bc-authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  const data = await safeJson(res);

  if (!res.ok) {
    throw new Error(`bc-authorize failed (${res.status}): ${data.error} — ${data.error_description}`);
  }

  return data; // { auth_req_id, expires_in, interval }
}

async function pollForDecision(authReqId, intervalSeconds) {
  let intervalMs = Math.min((intervalSeconds || 5) * 1000, MAX_POLL_INTERVAL_MS);
  const deadline = Date.now() + MAX_WAIT_MS;

  while (Date.now() < deadline) {
    await sleep(intervalMs);

    const body = new URLSearchParams({
      grant_type:    'urn:openid:params:grant-type:ciba',
      auth_req_id:   authReqId,
      client_id:     CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });

    const res = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const data = await safeJson(res);

    if (res.ok && data.access_token) return 'approved';

    switch (data.error) {
      case 'authorization_pending':
        continue;
      case 'slow_down':
        intervalMs = Math.min(intervalMs + 5000, MAX_POLL_INTERVAL_MS);
        continue;
      case 'access_denied':
        return 'denied';
      case 'expired_token':
        return 'expired';
      default:
        throw new Error(`Unexpected token poll error: ${data.error} — ${data.error_description}`);
    }
  }

  return 'expired'; // 120 s ceiling exceeded — always abort, never proceed
}

// ── Public API ────────────────────────────────────────────────────────────────

// initiateCIBA({ event_type, payload, user_id })
// Returns: 'approved' | 'denied' | 'expired'
async function initiateCIBA({ event_type, payload = {}, user_id }) {
  if (!user_id) throw new Error('[ciba-handler] user_id is required');

  const bindingMessage = buildBindingMessage(event_type, payload);
  console.log(`[ciba-handler] Sending CIBA email for ${event_type} (user: ${user_id})`);
  console.log(`[ciba-handler] Binding message: "${bindingMessage}"`);

  const { auth_req_id, interval } = await bcAuthorize(user_id, bindingMessage);
  return pollForDecision(auth_req_id, interval);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { initiateCIBA };
