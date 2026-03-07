PURCHASE_AUTO_APPROVE_LIMIT = 200.0
PURCHASE_HIGH_RISK_LIMIT = 1000.0

BLOCKED_VENDORS = {"shadycorp", "fakellc", "scam-store"}
UNUSUAL_VENDORS = {"unknown-merchant", "overseas-supplier"}
UNUSUAL_CATEGORIES = {"cryptocurrency", "gambling", "adult"}

INTERNAL_EMAIL_DOMAINS = {"company.com", "corp.company.com"}

EXPORT_SMALL_ROW_LIMIT = 500
EXPORT_LARGE_ROW_LIMIT = 10000

RISK_THRESHOLDS = {
    "approved": 30,
    "needs_confirmation": 70,
}
