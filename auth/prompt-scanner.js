const DELETION_KEYWORDS = [
  'delete', 'remove', 'erase', 'wipe', 'destroy', 'purge', 'clear', 'drop', 'trash', 'unlink',
];

const PAYMENT_KEYWORDS = [
  'pay', 'payment', 'transfer', 'send money', 'charge', 'transaction',
  'purchase', 'buy', 'checkout', 'invoice', 'refund', 'wire', 'debit', 'billing',
];

// Build a word-boundary regex for a keyword. Handles multi-word phrases (e.g. "send money").
function buildWordBoundaryRegex(kw) {
  const escaped = kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
  return new RegExp(`\\b${escaped}\\b`, 'i');
}

const DELETION_REGEXES = DELETION_KEYWORDS.map((kw) => ({ kw, re: buildWordBoundaryRegex(kw) }));
const PAYMENT_REGEXES = PAYMENT_KEYWORDS.map((kw) => ({ kw, re: buildWordBoundaryRegex(kw) }));

function matchKeywords(text, regexList) {
  return regexList.filter(({ re }) => re.test(text)).map(({ kw }) => kw);
}

function scanPrompt(text) {
  if (typeof text !== 'string') return { triggered: false, category: null, matchedKeywords: [] };

  const deletionMatches = matchKeywords(text, DELETION_REGEXES);
  const paymentMatches = matchKeywords(text, PAYMENT_REGEXES);

  if (deletionMatches.length === 0 && paymentMatches.length === 0) {
    return { triggered: false, category: null, matchedKeywords: [] };
  }

  // deletion takes priority (higher risk)
  if (deletionMatches.length > 0) {
    return { triggered: true, category: 'deletion', matchedKeywords: deletionMatches };
  }

  return { triggered: true, category: 'payment', matchedKeywords: paymentMatches };
}

module.exports = { scanPrompt };
