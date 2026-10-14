"""
Unit tests for the central scoring engine and recommendation logic.
Tests orchestration, provider fallbacks, recommendation assignment, and score thresholds.
"""

import pytest
from scoring.engine import (
    run_url_analysis,
    run_message_analysis,
    build_recommendations,
)
from scoring.indicators import get_risk_level, get_classification
from models import Indicator, Severity, ScanType, RiskLevel


def test_risk_level_thresholds():
    """Verify standard thresholds match documented engineering specifications."""
    assert get_risk_level(0) == "low"
    assert get_risk_level(24) == "low"
    assert get_risk_level(25) == "moderate"
    assert get_risk_level(49) == "moderate"
    assert get_risk_level(50) == "high"
    assert get_risk_level(74) == "high"
    assert get_risk_level(75) == "critical"
    assert get_risk_level(100) == "critical"


def test_build_recommendations_low_risk():
    """Low risk should return standard hygiene guidance."""
    recs = build_recommendations("low", "url", [])
    assert len(recs) >= 2
    assert any("No action required" in r for r in recs)


def test_build_recommendations_high_risk_with_sensitive():
    """High risk with sensitive data requests should include bank freeze instructions."""
    ind = [
        Indicator(
            severity=Severity.CRITICAL,
            name="Request for Sensitive Personal Data",
            detail="password requested",
            points=28,
            source="local",
        )
    ]
    recs = build_recommendations("high", "message", ind)
    assert any("bank" in r.lower() or "freeze" in r.lower() for r in recs)


@pytest.mark.asyncio
async def test_run_url_analysis_without_providers():
    """Engine must function cleanly and return complete schema even when all external APIs are missing."""
    result = await run_url_analysis(
        raw_url="http://paypa1-secure.account-verify.tk/login?user=reset",
        providers={},
        gemini_provider=None,
    )
    assert result.scan_id is not None
    assert result.scan_type == ScanType.URL
    assert result.risk_score > 0
    assert result.risk_level in [RiskLevel.MODERATE, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert len(result.indicators) > 0
    assert result.ai_available is False
    assert any(p.name == "VirusTotal" for p in result.providers)
    assert any(p.name == "URLhaus" for p in result.providers)
    assert any(p.name == "Gemini AI" for p in result.providers)


@pytest.mark.asyncio
async def test_run_message_analysis_without_providers():
    """Engine must function cleanly for messages without external APIs."""
    result = await run_message_analysis(
        message="URGENT: Your account has been suspended. Send your password to restore access.",
        providers={},
        gemini_provider=None,
    )
    assert result.scan_id is not None
    assert result.scan_type == ScanType.MESSAGE
    assert result.risk_score >= 30
    assert result.risk_level in [RiskLevel.MODERATE, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert len(result.recommendations) > 0
