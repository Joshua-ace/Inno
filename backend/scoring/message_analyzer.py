"""
Message threat analysis engine.
Detects social engineering patterns, scam tactics, and suspicious content
in SMS, email, and chat messages.
"""

import re
from typing import Optional

from scoring.indicators import (
    MESSAGE_WEIGHTS, URGENCY_TERMS, THREAT_TERMS, SENSITIVE_DATA_TERMS,
    PRIZE_TERMS, PAYMENT_TERMS, GENERIC_GREETINGS, BRAND_NAMES,
    DELIVERY_TERMS, RECRUITMENT_TERMS, GOVERNMENT_TERMS,
)
from models import Indicator, Severity


def analyze_message(message: str) -> dict:
    """
    Analyze a message for phishing, scam, and social engineering indicators.

    Returns a dict with:
        score: int (0-100)
        indicators: list[Indicator]
        extracted: dict (urls, emails, phones found in the message)
        error: Optional[str]
    """
    if not message or not message.strip():
        return {"error": "Message cannot be empty."}

    msg_lower = message.lower()
    score = 0
    indicators: list[Indicator] = []
    seen_categories: set[str] = set()

    # Extract embedded URLs, emails, phones
    url_pattern = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.IGNORECASE)
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    phone_pattern = re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}')

    found_urls = url_pattern.findall(message)
    found_emails = email_pattern.findall(message)
    found_phones = phone_pattern.findall(message)

    extracted = {
        "urls": found_urls[:10],
        "emails": found_emails[:5],
        "phones": found_phones[:5],
    }

    def add_indicator(category: str, severity: Severity, name: str, detail: str, points: int):
        nonlocal score
        if category in seen_categories:
            return
        seen_categories.add(category)
        capped_points = min(points, 100 - score)
        score += capped_points
        indicators.append(Indicator(
            severity=severity,
            name=name,
            detail=detail,
            points=capped_points,
            source="local",
        ))

    # ── Check 1: Urgency tactics ───────────────────────
    found_urgency = [t for t in URGENCY_TERMS if t in msg_lower]
    if found_urgency:
        points = min(
            len(found_urgency) * MESSAGE_WEIGHTS["urgency_pressure"],
            MESSAGE_WEIGHTS["urgency_pressure_cap"],
        )
        add_indicator(
            "urgency",
            Severity.WARNING,
            "Urgency Pressure Tactics",
            f"Detected {len(found_urgency)} urgency trigger(s) including: "
            f"\"{found_urgency[0]}\". This technique is specifically designed "
            "to prevent you from pausing to verify the sender's identity.",
            points,
        )

    # ── Check 2: Threatening consequences ──────────────
    found_threats = [t for t in THREAT_TERMS if t in msg_lower]
    if found_threats:
        points = min(
            len(found_threats) * MESSAGE_WEIGHTS["threatening_consequences"],
            MESSAGE_WEIGHTS["threatening_consequences_cap"],
        )
        add_indicator(
            "threats",
            Severity.CRITICAL,
            "Threatening Consequences",
            f"Message uses fear-inducing language: "
            f"\"{'\", \"'.join(found_threats[:2])}\". Threatening account "
            "closures, legal action, or arrest is a documented scam technique "
            "to override rational judgment.",
            points,
        )

    # ── Check 3: Sensitive data requests ───────────────
    found_sensitive = [t for t in SENSITIVE_DATA_TERMS if t in msg_lower]
    if found_sensitive:
        points = min(
            len(found_sensitive) * MESSAGE_WEIGHTS["sensitive_data_request"],
            MESSAGE_WEIGHTS["sensitive_data_request_cap"],
        )
        add_indicator(
            "sensitive_data",
            Severity.CRITICAL,
            "Request for Sensitive Personal Data",
            f"Explicitly requests: {', '.join(found_sensitive[:3])}. "
            "No legitimate financial institution, government body, or service "
            "provider asks for this information through an unsolicited message.",
            points,
        )

    # ── Check 4: Prize/lottery claims ──────────────────
    found_prize = [t for t in PRIZE_TERMS if t in msg_lower]
    if found_prize:
        points = min(
            len(found_prize) * MESSAGE_WEIGHTS["prize_lottery_claim"],
            MESSAGE_WEIGHTS["prize_lottery_claim_cap"],
        )
        add_indicator(
            "prize",
            Severity.WARNING,
            "Unsolicited Prize or Reward Claim",
            f"Contains: \"{found_prize[0]}\". You cannot win a contest you did "
            "not enter. Messages claiming otherwise are almost universally "
            "phishing or advance-fee fraud.",
            points,
        )

    # ── Check 5: Generic greeting ──────────────────────
    if any(g in msg_lower for g in GENERIC_GREETINGS):
        add_indicator(
            "generic_greeting",
            Severity.INFO,
            "Generic, Non-Personalized Greeting",
            "Legitimate services address you by your registered name. A generic "
            "salutation is a sign the message was sent in bulk to many recipients.",
            MESSAGE_WEIGHTS["generic_greeting"],
        )

    # ── Check 6: Embedded URLs ─────────────────────────
    if found_urls:
        points = min(
            len(found_urls) * MESSAGE_WEIGHTS["embedded_urls"],
            MESSAGE_WEIGHTS["embedded_urls_cap"],
        )
        display = [u[:55] + '...' if len(u) > 55 else u for u in found_urls[:2]]
        add_indicator(
            "embedded_urls",
            Severity.WARNING,
            f"Contains {len(found_urls)} Link{'s' if len(found_urls) > 1 else ''}",
            f"Do not click links in unsolicited messages. Found: "
            f"{'; '.join(display)}. Navigate to the official site directly.",
            points,
        )

    # ── Check 7: Untraceable payment demands ───────────
    found_payment = [t for t in PAYMENT_TERMS if t in msg_lower]
    if found_payment:
        points = min(
            len(found_payment) * MESSAGE_WEIGHTS["untraceable_payment"],
            MESSAGE_WEIGHTS["untraceable_payment_cap"],
        )
        add_indicator(
            "payment",
            Severity.CRITICAL,
            "Untraceable Payment Demanded",
            f"Requests payment through: {', '.join(found_payment[:2])}. "
            "Government agencies, banks, and legitimate companies do not "
            "collect payment via gift cards, wire transfers, or cryptocurrency.",
            points,
        )

    # ── Check 8: Fake delivery notification ────────────
    found_delivery = [t for t in DELIVERY_TERMS if t in msg_lower]
    if found_delivery:
        add_indicator(
            "delivery",
            Severity.WARNING,
            "Suspicious Delivery Notification",
            f"Contains delivery-related language: \"{found_delivery[0]}\". "
            "Fake delivery notifications are a common phishing vector. Check "
            "your actual tracking directly on the carrier's official website.",
            MESSAGE_WEIGHTS["fake_delivery_notification"],
        )

    # ── Check 9: Recruitment/job scam ──────────────────
    found_recruitment = [t for t in RECRUITMENT_TERMS if t in msg_lower]
    if found_recruitment:
        add_indicator(
            "recruitment",
            Severity.WARNING,
            "Potential Recruitment Scam",
            f"Contains: \"{found_recruitment[0]}\". Unsolicited job offers "
            "promising easy income with no experience are a documented fraud "
            "pattern used to harvest personal information or collect fees.",
            MESSAGE_WEIGHTS["recruitment_scam"],
        )

    # ── Check 10: Government impersonation ─────────────
    found_gov = [t for t in GOVERNMENT_TERMS if t in msg_lower]
    if found_gov and score >= 10:
        add_indicator(
            "government",
            Severity.CRITICAL,
            "Government Service Impersonation",
            f"References government services: \"{found_gov[0]}\". Combined "
            "with other suspicious patterns, this message appears to impersonate "
            "a government agency. Official agencies do not send unsolicited "
            "messages requesting personal data or payment.",
            MESSAGE_WEIGHTS["government_impersonation"],
        )

    # ── Check 11: Brand impersonation ──────────────────
    found_brands = [b for b in BRAND_NAMES if b in msg_lower]
    if found_brands and score >= 18:
        add_indicator(
            "brand_impersonation",
            Severity.WARNING,
            "Probable Brand Impersonation",
            f"References: {', '.join(found_brands[:3])}. Combined with other "
            "red flags, this message appears to impersonate a trusted "
            "organization. Contact that organization directly using contact "
            "information from their official website.",
            MESSAGE_WEIGHTS["brand_impersonation"],
        )

    # ── Check 12: Suspicious email addresses ───────────
    if found_emails:
        suspicious_email_tlds = ['.tk', '.xyz', '.top', '.ml', '.ga', '.cf']
        suspicious_mails = [e for e in found_emails
                           if any(e.lower().endswith(tld) for tld in suspicious_email_tlds)]
        if suspicious_mails:
            add_indicator(
                "suspicious_email",
                Severity.WARNING,
                "Suspicious Email Address",
                f"Contains email from a high-risk domain: {suspicious_mails[0]}. "
                "Legitimate organizations use their own verified domain for email.",
                MESSAGE_WEIGHTS["suspicious_email_address"],
            )

    final_score = min(score, 100)

    return {
        "score": final_score,
        "indicators": indicators,
        "extracted": extracted,
        "metadata": {
            "extracted_urls": len(extracted["urls"]),
            "extracted_emails": len(extracted["emails"]),
            "extracted_phones": len(extracted["phones"]),
            "message_length": len(message),
        },
        "error": None,
    }
