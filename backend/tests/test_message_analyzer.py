"""
Unit tests for the suspicious message analyzer.
Tests social engineering tactics, scam patterns, sensitive data requests, and benign text.
"""

import pytest
from scoring.message_analyzer import analyze_message


def test_benign_message():
    """Everyday legitimate message should score 0 or very low with no critical indicators."""
    text = "Hi Alex, hope you are having a great week! Let us meet tomorrow at 10 AM for coffee."
    result = analyze_message(text)
    assert result["score"] == 0
    assert len(result["indicators"]) == 0


def test_urgency_and_threats():
    """Urgency words combined with suspension threats should be heavily penalized."""
    text = "URGENT: Your account has been suspended due to fraudulent activity. You must verify immediately."
    result = analyze_message(text)
    assert result["score"] >= 30
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Urgency" in name for name in indicator_names)
    assert any("Threatening" in name for name in indicator_names)


def test_sensitive_data_harvesting():
    """Requesting passwords, credit cards, or OTPs should trigger critical indicator."""
    text = "Please reply with your current password, credit card number, and CVV to confirm your identity."
    result = analyze_message(text)
    assert result["score"] >= 25
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Sensitive" in name for name in indicator_names)


def test_prize_lottery_scam():
    """Unsolicited winnings and prize claims should be detected."""
    text = "Congratulations! You have won $10,000 in the national lottery. Claim your reward today."
    result = analyze_message(text)
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Prize" in name for name in indicator_names)


def test_untraceable_payment_demand():
    """Demands for gift cards, cryptocurrency, or wire transfers should be flagged."""
    text = "Send payment immediately via Bitcoin or Apple gift cards to clear your outstanding IRS fine."
    result = analyze_message(text)
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Payment" in name for name in indicator_names)


def test_fake_delivery_notification():
    """Parcel delivery scam message should be detected."""
    text = "Your package cannot be delivered due to an incomplete address. Update your shipping details."
    result = analyze_message(text)
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Delivery" in name for name in indicator_names)


def test_embedded_url_extraction():
    """Embedded URLs in messages should be extracted and counted in metadata."""
    text = "Your account is locked. Visit http://verify-support.tk/now to unlock your account."
    result = analyze_message(text)
    assert result["metadata"]["extracted_urls"] == 1
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Link" in name for name in indicator_names)


def test_score_caps_prevent_overflow():
    """A message with repetitive urgency terms should not score infinite points; category caps apply."""
    repetitive_text = "urgent immediately right now act now limited time expires last chance final notice today only must verify"
    result = analyze_message(repetitive_text)
    assert result["score"] <= 30  # urgency cap is 22 in indicators.py
    assert result["score"] <= 100
