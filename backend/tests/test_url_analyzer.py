"""
Unit tests for the URL threat analyzer.
Tests structural inspection, indicator detection, weight calculation, and edge cases.
"""

import pytest
from scoring.url_analyzer import analyze_url


def test_benign_url():
    """Legitimate HTTPS URL should produce a 0 or very low score with no critical indicators."""
    result = analyze_url("https://github.com/torvalds/linux")
    assert not result.get("error")
    assert result["score"] == 0
    assert len(result["indicators"]) == 0
    assert result["metadata"]["registered_domain"] == "github.com"
    assert result["metadata"]["protocol"] == "https"


def test_http_unencrypted():
    """Unencrypted HTTP connection should be flagged."""
    result = analyze_url("http://example.com")
    assert result["score"] > 0
    indicator_names = [i.name for i in result["indicators"]]
    assert any("No Encryption" in name for name in indicator_names)


def test_ip_address_host():
    """Raw IP address hostname should be flagged with high severity."""
    result = analyze_url("http://192.168.1.1/admin/login")
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Raw IP Address" in name for name in indicator_names)
    assert result["score"] >= 35


def test_suspicious_tld():
    """High-risk TLD should trigger warning indicator."""
    result = analyze_url("https://account-portal.tk/login")
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Suspicious Domain Extension" in name for name in indicator_names)


def test_at_symbol_credential_injection():
    """URL containing @ symbol used for credential spoofing should be flagged."""
    result = analyze_url("https://paypal.com@attacker-site.com/verify")
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Credential Injection" in name for name in indicator_names)
    assert result["score"] >= 30


def test_phishing_keywords():
    """URL with multiple phishing terms should be flagged."""
    result = analyze_url("https://secure-login-verify-account.com/auth")
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Phishing Keywords" in name for name in indicator_names)


def test_url_shortener():
    """Known URL shortener should be detected."""
    result = analyze_url("https://bit.ly/3xYqz9")
    indicator_names = [i.name for i in result["indicators"]]
    assert any("URL Shortener" in name for name in indicator_names)


def test_deep_subdomains():
    """More than 4 hostname components should be flagged."""
    result = analyze_url("https://a.b.c.d.legit-lookalike.com/test")
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Deep Subdomain" in name for name in indicator_names)


def test_hyphen_heavy_domain():
    """Multiple hyphens in domain label should be flagged."""
    result = analyze_url("https://verify-secure-bank-login-update.com")
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Hyphen" in name for name in indicator_names)


def test_punycode_domain():
    """Internationalized domain name (IDN / punycode) should be flagged."""
    result = analyze_url("https://xn--pple-43d.com/login")
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Punycode" in name for name in indicator_names)


def test_non_standard_port():
    """Unusual port number should be flagged."""
    result = analyze_url("https://example.com:9876/index.html")
    indicator_names = [i.name for i in result["indicators"]]
    assert any("Non-Standard Port" in name for name in indicator_names)


def test_score_never_exceeds_100():
    """Compounded indicators must never produce a score above 100."""
    nasty_url = "http://192.168.1.1:9999/paypal/login/verify/secure/update/password/@evil.tk/a//b/c?token=123"
    result = analyze_url(nasty_url)
    assert result["score"] <= 100
    assert result["score"] >= 70


def test_malformed_url_handling():
    """Malformed or unparseable input should return an error dict, not raise an exception."""
    result = analyze_url("://not-a-valid-url")
    assert "error" in result or result.get("score") is not None
