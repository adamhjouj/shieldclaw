const DELETION_KEYWORDS = [
  'delete', 'remove', 'erase', 'wipe', 'destroy', 'purge', 'clear', 'drop', 'trash', 'unlink',
];

const PAYMENT_KEYWORDS = [
  'pay', 'payment', 'transfer', 'send money', 'charge', 'transaction',
  'purchase', 'buy', 'checkout', 'invoice', 'refund', 'wire', 'debit', 'billing',
];

function matchKeywords(text, keywords) {
  return keywords.filter((kw) => text.includes(kw));
}

function scanPrompt(text) {
  const lower = text.toLowerCase();

  const deletionMatches = matchKeywords(lower, DELETION_KEYWORDS);
  const paymentMatches = matchKeywords(lower, PAYMENT_KEYWORDS);

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
