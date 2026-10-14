"""
Indicator definitions and weight configurations for the detection engine.
All weights are documented with rationale. Thresholds are engineering defaults,
not scientifically validated probabilities.

Risk Level Thresholds:
    0-24:  Low       - Minor indicators, likely benign
    25-49: Moderate  - Several suspicious patterns, exercise caution
    50-74: High      - Strong evidence of malicious intent
    75-100: Critical - Multiple confirmed threat indicators
"""

# ── URL Indicator Weights ──────────────────────────────
# Each weight reflects how strongly the indicator correlates with phishing.

URL_WEIGHTS = {
    # Transport security
    "http_no_encryption": 12,

    # Domain identity
    "ip_address_host": 35,
    "suspicious_tld": 18,
    "deep_subdomains": 18,         # 5+ subdomain levels
    "hyphen_heavy_domain": 14,     # 3+ hyphens
    "digit_heavy_hostname": 8,     # 5+ digits in hostname
    "punycode_domain": 15,         # internationalized domain name

    # URL manipulation
    "at_symbol_injection": 30,
    "url_shortener": 18,
    "excessive_length": 8,         # > 120 characters
    "non_standard_port": 14,
    "double_slash_path": 7,
    "encoded_characters": 10,      # excessive percent encoding

    # Intent signals
    "phishing_keywords_high": 22,  # 3+ keywords
    "phishing_keywords_low": 6,    # per keyword, 1-2 found
    "brand_in_subdomain": 20,      # trusted brand as subdomain, not registered domain
    "suspicious_path_keywords": 10,  # /login, /verify, /account in path

    # Threat intelligence
    "virustotal_malicious": 40,
    "virustotal_suspicious": 20,
    "urlhaus_match": 45,
}

# ── Message Indicator Weights ──────────────────────────

MESSAGE_WEIGHTS = {
    # Social engineering tactics
    "urgency_pressure": 8,         # per term, capped at 22
    "urgency_pressure_cap": 22,
    "threatening_consequences": 10, # per term, capped at 30
    "threatening_consequences_cap": 30,

    # Data harvesting
    "sensitive_data_request": 14,  # per term, capped at 40
    "sensitive_data_request_cap": 40,

    # Scam patterns
    "prize_lottery_claim": 10,     # per term, capped at 30
    "prize_lottery_claim_cap": 30,
    "generic_greeting": 10,
    "untraceable_payment": 14,     # per term, capped at 35
    "untraceable_payment_cap": 35,

    # Identity and links
    "embedded_urls": 8,            # per URL, capped at 20
    "embedded_urls_cap": 20,
    "brand_impersonation": 14,     # only when combined with other flags
    "suspicious_phone_number": 8,
    "suspicious_email_address": 10,

    # Delivery and job scams
    "fake_delivery_notification": 12,
    "recruitment_scam": 12,
    "government_impersonation": 15,

    # Threat intelligence on embedded URLs
    "embedded_url_malicious": 35,
    "embedded_url_suspicious": 18,
}

# ── Risk Level Thresholds ──────────────────────────────

RISK_THRESHOLDS = [
    (75, "critical"),
    (50, "high"),
    (25, "moderate"),
    (0,  "low"),
]


def get_risk_level(score: int) -> str:
    """Map a 0-100 score to a risk level string."""
    for threshold, level in RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return "low"


def get_classification(risk_level: str, scan_type: str) -> str:
    """Generate a human-readable classification string."""
    classifications = {
        "critical": {
            "url": "Likely Phishing or Malicious URL",
            "message": "Likely Scam or Phishing Message",
        },
        "high": {
            "url": "Suspicious URL with Multiple Risk Indicators",
            "message": "Suspicious Message with Strong Scam Indicators",
        },
        "moderate": {
            "url": "URL with Several Concerning Patterns",
            "message": "Message with Several Suspicious Patterns",
        },
        "low": {
            "url": "No Significant Threats Detected in URL",
            "message": "No Significant Threats Detected in Message",
        },
    }
    return classifications.get(risk_level, {}).get(scan_type, "Analysis Complete")


# ── Known Lists ────────────────────────────────────────

SUSPICIOUS_TLDS = frozenset([
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
    ".loan", ".win", ".download", ".racing", ".click", ".review",
    ".party", ".science", ".men", ".gdn", ".date", ".faith",
    ".stream", ".online", ".icu", ".buzz", ".rest", ".surf",
])

URL_SHORTENERS = frozenset([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
    "is.gd", "buff.ly", "tiny.cc", "ht.ly", "rb.gy", "shorturl.at",
    "cutt.ly", "adf.ly", "v.gd", "bl.ink", "soo.gd", "s.id",
    "rebrand.ly", "han.gl", "clck.ru",
])

PHISHING_KEYWORDS = frozenset([
    "login", "signin", "sign-in", "verify", "verification", "update",
    "confirm", "secure", "security", "password", "credential", "wallet",
    "recover", "auth", "webscr", "banking", "account-update", "suspend",
    "reactivate", "unlock", "validate", "authenticate", "restore",
])

BRAND_NAMES = frozenset([
    "paypal", "amazon", "apple", "google", "microsoft", "netflix",
    "facebook", "instagram", "whatsapp", "chase", "wells fargo",
    "bank of america", "citibank", "irs", "fbi", "fedex", "ups",
    "usps", "dhl", "dropbox", "linkedin", "twitter", "telegram",
    "spotify", "coinbase", "binance", "metamask",
])

URGENCY_TERMS = [
    "urgent", "immediately", "right now", "act now", "limited time",
    "expires", "expiring", "last chance", "final notice", "action required",
    "respond immediately", "within 24 hours", "within 48 hours",
    "today only", "must verify", "must respond", "time sensitive",
    "deadline", "account will be", "running out",
]

THREAT_TERMS = [
    "suspended", "terminated", "closed", "blocked", "restricted",
    "legal action", "arrested", "police", "irs", "fine", "penalty",
    "lawsuit", "prosecute", "criminal", "warrant", "deactivated",
    "fraud detected", "permanently closed", "violation", "unauthorized",
    "seized", "frozen",
]

SENSITIVE_DATA_TERMS = [
    "password", "pin", "social security", "ssn", "credit card",
    "debit card", "bank account", "account number", "routing number",
    "cvv", "date of birth", "mother's maiden", "passport number",
    "national id", "one-time password", "otp", "security code",
    "tax id", "driver's license", "aadhaar",
]

PRIZE_TERMS = [
    "you have won", "you've won", "you are the winner", "lottery",
    "lucky winner", "inheritance", "you have been selected",
    "congratulations", "unclaimed funds", "claim your reward",
    "free iphone", "you are selected", "prize claim", "cash prize",
    "million dollars", "selected as winner",
]

PAYMENT_TERMS = [
    "send money", "wire transfer", "western union", "moneygram",
    "bitcoin", "cryptocurrency", "gift card", "itunes card",
    "google play card", "amazon card", "transfer funds", "pay now",
    "payment required", "debt collection", "overdue balance",
    "crypto wallet", "btc", "ethereum", "usdt",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear account holder", "dear member",
    "dear client", "hello customer", "valued customer", "dear sir",
    "dear madam", "dear sir/madam", "dear beneficiary", "dear winner",
    "dear valued",
]

DELIVERY_TERMS = [
    "package delivery", "shipment tracking", "delivery failed",
    "reschedule delivery", "customs clearance", "parcel held",
    "delivery attempt", "tracking number", "undelivered package",
    "package cannot be delivered", "incomplete address", "shipping details",
    "update your address", "delivery fee",
]

RECRUITMENT_TERMS = [
    "work from home", "earn money fast", "no experience needed",
    "guaranteed income", "make money online", "easy money",
    "financial freedom", "part time job", "high paying",
    "weekly salary", "daily earnings",
]

GOVERNMENT_TERMS = [
    "irs", "tax refund", "social security administration",
    "government grant", "stimulus check", "tax return",
    "internal revenue", "customs department", "immigration",
]
