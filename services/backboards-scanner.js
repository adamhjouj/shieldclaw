const DELETION_KEYWORDS = [
  'delete', 'remove', 'erase', 'wipe', 'destroy', 'purge',
  'unlink', 'drop', 'clear', 'eliminate',
];

const PAYMENT_KEYWORDS = [
  'pay', 'payment', 'transfer', 'transaction', 'charge', 'send money',
  'withdraw', 'debit', 'invoice', 'purchase', 'checkout', 'refund', 'wire',
];

const FILE_OP_KEYWORDS = [
  'overwrite', 'replace file', 'truncate', 'shred',
];

// Priority order for event_type derivation: deletion > file_op > payment
const PRIORITY = ['deletion', 'file_op', 'payment'];

const EVENT_TYPE_MAP = {
  deletion: 'file.delete',
  file_op:  'file.operation',
  payment:  'payment.initiate',
};

function buildWordBoundaryRegex(kw) {
  const escaped = kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
  return new RegExp(`\\b${escaped}\\b`, 'i');
}

const REGEXES = {
  deletion: DELETION_KEYWORDS.map((kw) => ({ kw, re: buildWordBoundaryRegex(kw) })),
  payment:  PAYMENT_KEYWORDS.map((kw) => ({ kw, re: buildWordBoundaryRegex(kw) })),
  file_op:  FILE_OP_KEYWORDS.map((kw) => ({ kw, re: buildWordBoundaryRegex(kw) })),
};

function matchCategory(text, regexList) {
  return regexList.filter(({ re }) => re.test(text)).map(({ kw }) => kw);
}

// Calls the Backboards.io API to log the scanned text (for memory/audit),
// then performs local keyword detection.
// options: { threadId?, memory? } — if threadId is provided, the text is
// forwarded to Backboard.io for memory extraction regardless of scan result.
async function scanForSensitiveContent(text, options = {}) {
  if (typeof text !== 'string') {
    return { isSensitive: false, event_type: null, keywords_found: [], raw_text: text };
  }

  // ── Backboards.io API logging ──
  if (options.threadId) {
    await logToBackboard(options.threadId, text, options.memory).catch((err) => {
      console.warn('[backboards-scanner] Backboard.io logging failed (non-fatal):', err.message);
    });
  }

  // ── Local keyword detection ──
  const matches = {};
  for (const category of PRIORITY) {
    matches[category] = matchCategory(text, REGEXES[category]);
  }

  const allFound = [...matches.deletion, ...matches.file_op, ...matches.payment];

  if (allFound.length === 0) {
    return { isSensitive: false, event_type: null, keywords_found: [], raw_text: text };
  }

  // Pick highest-priority triggered category
  const triggeredCategory = PRIORITY.find((cat) => matches[cat].length > 0);
  const event_type = EVENT_TYPE_MAP[triggeredCategory];

  return {
    isSensitive: true,
    event_type,
    keywords_found: allFound,
    raw_text: text,
  };
}

async function logToBackboard(threadId, content, memory = 'Auto') {
  const apiKey = process.env.BACKBOARDS_API_KEY;
  if (!apiKey) throw new Error('BACKBOARDS_API_KEY is not set');

  const baseUrl = process.env.BACKBOARD_BASE_URL || '';

  const res = await fetch(`${baseUrl}/threads/${threadId}/messages`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({ content, memory, stream: false }),
  });

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(`Backboard.io error ${res.status}: ${data.error || data.message || 'unknown'}`);
  }

  return res.json().catch(() => ({}));
}

module.exports = { scanForSensitiveContent };
