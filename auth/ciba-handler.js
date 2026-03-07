const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;

const DEFAULT_POLL_INTERVAL_MS = 5000;

async function initiateCibaRequest(userId, bindingMessage) {
  const loginHint = JSON.stringify({
    format: 'iss_sub',
    iss: `https://${AUTH0_DOMAIN}/`,
    sub: userId,
  });

  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope: 'openid',
    login_hint: loginHint,
    binding_message: bindingMessage,
    request_expiry: '300',
  });

  const res = await fetch(`https://${AUTH0_DOMAIN}/bc-authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(`bc-authorize failed: ${data.error} — ${data.error_description}`);
  }

  return data; // { auth_req_id, expires_in, interval }
}

async function pollForApproval(authReqId, expiresIn, intervalSeconds) {
  let intervalMs = (intervalSeconds || 5) * 1000;
  const deadline = Date.now() + expiresIn * 1000;

  while (Date.now() < deadline) {
    await sleep(intervalMs);

    const body = new URLSearchParams({
      grant_type: 'urn:openid:params:grant-type:ciba',
      auth_req_id: authReqId,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });

    const res = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const data = await res.json();

    if (res.ok && data.access_token) {
      return 'approved';
    }

    const error = data.error;

    if (error === 'authorization_pending') {
      continue;
    } else if (error === 'slow_down') {
      intervalMs += 5000;
      continue;
    } else if (error === 'access_denied') {
      return 'denied';
    } else if (error === 'expired_token') {
      return 'expired';
    } else {
      throw new Error(`Unexpected token error: ${error} — ${data.error_description}`);
    }
  }

  return 'expired';
}

async function requestCibaApproval(userId, bindingMessage) {
  const { auth_req_id, expires_in, interval } = await initiateCibaRequest(userId, bindingMessage);
  return pollForApproval(auth_req_id, expires_in, interval);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { requestCibaApproval };
