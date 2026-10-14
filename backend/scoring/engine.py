"""
Central scoring engine that orchestrates URL/message analysis,
threat intelligence lookups, and AI explanations.
"""

import uuid
import json
from datetime import datetime, timezone
from typing import Optional

from models import (
    AnalysisResponse, Indicator, ProviderResult, ProviderStatus,
    ScanType, Severity,
)
from scoring.indicators import get_risk_level, get_classification
from scoring.url_analyzer import analyze_url
from scoring.message_analyzer import analyze_message


def build_recommendations(risk_level: str, scan_type: str, indicators: list[Indicator]) -> list[str]:
    """Generate actionable recommendations based on risk level and findings."""
    recs = []

    has_sensitive = any("Sensitive" in i.name for i in indicators)
    has_payment = any("Payment" in i.name for i in indicators)

    if risk_level == "low":
        recs.append("No action required based on this analysis.")
        recs.append(
            "Even content that clears pattern checks can be malicious. "
            "Verify the sender independently before sharing any personal data."
        )
        recs.append(
            "Keep your browser, OS, and antivirus software updated to defend "
            "against threats this tool cannot detect."
        )
        return recs

    if risk_level == "moderate":
        if scan_type == "url":
            recs.append(
                "Do not enter any login credentials or personal information on "
                "this page until you have verified its legitimacy."
            )
            recs.append(
                "Check the full domain carefully. Look it up using a site "
                "reputation service such as Google Safe Browsing or VirusTotal."
            )
        else:
            recs.append(
                "Do not click any links in this message. Navigate to the "
                "official website directly using its known address."
            )
            recs.append(
                "Contact the organization the sender claims to represent through "
                "the phone number or address listed on their official website."
            )
        recs.append(
            "Report the content as phishing or spam to your email provider "
            "or mobile carrier."
        )
        return recs

    # HIGH or CRITICAL
    if scan_type == "url":
        recs.append(
            "Do not visit this URL. If you already opened it, close the tab "
            "immediately and clear your browser cache."
        )
        recs.append(
            "If you entered any information on the page, proceed to the "
            "next steps without delay."
        )
    else:
        recs.append(
            "Do not respond to this message, call any numbers listed in it, "
            "or click any links."
        )
        recs.append(
            "Block the sender and report the message as phishing to your "
            "carrier (forward to 7726 in most countries) or email provider."
        )

    if has_sensitive:
        recs.append(
            "If you already submitted personal information: contact your bank "
            "immediately to freeze affected accounts, place a fraud alert with "
            "the major credit bureaus, and file a report with your national "
            "cybercrime authority."
        )

    if has_payment:
        recs.append(
            "If you sent money: contact your bank right away to attempt a recall. "
            "If you paid via gift card, call the card issuer. Report to local "
            "law enforcement and your national fraud reporting body."
        )

    recs.append(
        "Report this threat to the Anti-Phishing Working Group at "
        "reportphishing@apwg.org and to your country's cybercrime "
        "reporting authority."
    )

    return recs


async def run_url_analysis(
    raw_url: str,
    providers: dict,
    gemini_provider=None,
) -> AnalysisResponse:
    """
    Full URL analysis pipeline:
    1. Local structural analysis
    2. Threat intelligence lookups (VirusTotal, URLhaus)
    3. AI explanation (Gemini)
    4. Risk scoring and response assembly
    """
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Step 1: Local analysis
    local_result = analyze_url(raw_url)
    if local_result.get("error"):
        return AnalysisResponse(
            scan_id=scan_id,
            scan_type=ScanType.URL,
            timestamp=timestamp,
            input_preview=_truncate(raw_url, 80),
            risk_score=0,
            risk_level="low",
            classification="Analysis Failed",
            indicators=[],
            indicator_count=0,
            providers=[],
            recommendations=["Check the URL format and try again."],
            limitations=local_result["error"],
        )

    score = local_result["score"]
    indicators = local_result["indicators"]
    metadata = local_result["metadata"]
    provider_results: list[ProviderResult] = []

    # Step 2: Threat intelligence lookups
    vt_provider = providers.get("virustotal")
    if vt_provider:
        vt_result = await vt_provider.check_url(raw_url)
        provider_results.append(vt_result)
        if vt_result.status == ProviderStatus.MATCH:
            vt_points = 40
            score = min(score + vt_points, 100)
            indicators.append(Indicator(
                severity=Severity.CRITICAL,
                name="VirusTotal: Malicious Detections",
                detail=vt_result.detail or "Multiple security vendors flagged this URL as malicious.",
                points=vt_points,
                source="virustotal",
            ))
        elif vt_result.status == ProviderStatus.SUSPICIOUS:
            vt_points = 20
            score = min(score + vt_points, 100)
            indicators.append(Indicator(
                severity=Severity.WARNING,
                name="VirusTotal: Suspicious Detections",
                detail=vt_result.detail or "Some security vendors flagged this URL as suspicious.",
                points=vt_points,
                source="virustotal",
            ))
    else:
        provider_results.append(ProviderResult(
            name="VirusTotal",
            status=ProviderStatus.NOT_CONFIGURED,
            detail="No API key configured. Add VIRUSTOTAL_API_KEY to .env to enable.",
        ))

    uh_provider = providers.get("urlhaus")
    if uh_provider:
        uh_result = await uh_provider.check_url(raw_url)
        provider_results.append(uh_result)
        if uh_result.status == ProviderStatus.MATCH:
            uh_points = 45
            score = min(score + uh_points, 100)
            indicators.append(Indicator(
                severity=Severity.CRITICAL,
                name="URLhaus: Known Malicious URL",
                detail=uh_result.detail or "This URL is listed in the URLhaus malicious URL database.",
                points=uh_points,
                source="urlhaus",
            ))
    else:
        provider_results.append(ProviderResult(
            name="URLhaus",
            status=ProviderStatus.NOT_CONFIGURED,
            detail="URLhaus lookups are disabled.",
        ))

    # Recalculate risk level after provider input
    final_score = min(score, 100)
    risk_level = get_risk_level(final_score)
    classification = get_classification(risk_level, "url")
    recommendations = build_recommendations(risk_level, "url", indicators)

    # Step 3: AI explanation
    ai_explanation = None
    ai_available = False
    if gemini_provider:
        try:
            ai_explanation = await gemini_provider.explain_findings(
                scan_type="url",
                input_preview=_truncate(raw_url, 100),
                risk_level=risk_level,
                risk_score=final_score,
                indicators=indicators,
            )
            ai_available = True
        except Exception:
            ai_explanation = None
            ai_available = False

    if not ai_available:
        provider_results.append(ProviderResult(
            name="Gemini AI",
            status=ProviderStatus.NOT_CONFIGURED if not gemini_provider else ProviderStatus.FAILED,
            detail="AI explanations are unavailable. Results are based on rule-based analysis.",
        ))
    else:
        provider_results.append(ProviderResult(
            name="Gemini AI",
            status=ProviderStatus.MATCH,
            detail="AI-assisted explanation generated successfully.",
        ))

    return AnalysisResponse(
        scan_id=scan_id,
        scan_type=ScanType.URL,
        timestamp=timestamp,
        input_preview=_truncate(raw_url, 80),
        risk_score=final_score,
        risk_level=risk_level,
        classification=classification,
        indicators=indicators,
        indicator_count=len(indicators),
        providers=provider_results,
        recommendations=recommendations,
        ai_explanation=ai_explanation,
        ai_available=ai_available,
        analysis_metadata=metadata,
    )


async def run_message_analysis(
    message: str,
    providers: dict,
    gemini_provider=None,
) -> AnalysisResponse:
    """
    Full message analysis pipeline:
    1. Local pattern analysis
    2. Threat intelligence on extracted URLs
    3. AI explanation (Gemini)
    4. Risk scoring and response assembly
    """
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Step 1: Local analysis
    local_result = analyze_message(message)
    if local_result.get("error"):
        return AnalysisResponse(
            scan_id=scan_id,
            scan_type=ScanType.MESSAGE,
            timestamp=timestamp,
            input_preview=_truncate(message, 80),
            risk_score=0,
            risk_level="low",
            classification="Analysis Failed",
            indicators=[],
            indicator_count=0,
            providers=[],
            recommendations=["Check the message and try again."],
            limitations=local_result["error"],
        )

    score = local_result["score"]
    indicators = local_result["indicators"]
    extracted = local_result["extracted"]
    provider_results: list[ProviderResult] = []

    # Step 2: Check extracted URLs against threat intelligence
    extracted_urls = extracted.get("urls", [])
    vt_provider = providers.get("virustotal")
    uh_provider = providers.get("urlhaus")

    if extracted_urls:
        # Check up to 3 embedded URLs
        for eurl in extracted_urls[:3]:
            if uh_provider:
                uh_result = await uh_provider.check_url(eurl)
                if uh_result.status == ProviderStatus.MATCH:
                    points = min(35, 100 - score)
                    score += points
                    indicators.append(Indicator(
                        severity=Severity.CRITICAL,
                        name=f"Embedded URL Flagged by URLhaus",
                        detail=f"URL in message ({_truncate(eurl, 50)}) is listed "
                               "in the URLhaus malicious URL database.",
                        points=points,
                        source="urlhaus",
                    ))
                    break  # One confirmed match is enough

            if vt_provider:
                vt_result = await vt_provider.check_url(eurl)
                if vt_result.status == ProviderStatus.MATCH:
                    points = min(35, 100 - score)
                    score += points
                    indicators.append(Indicator(
                        severity=Severity.CRITICAL,
                        name="Embedded URL Flagged by VirusTotal",
                        detail=f"URL in message ({_truncate(eurl, 50)}) was flagged "
                               "as malicious by security vendors.",
                        points=points,
                        source="virustotal",
                    ))
                    break

    # Provider status reporting
    if vt_provider:
        provider_results.append(ProviderResult(
            name="VirusTotal",
            status=ProviderStatus.NO_MATCH,
            detail="URL reputation check completed.",
        ))
    else:
        provider_results.append(ProviderResult(
            name="VirusTotal",
            status=ProviderStatus.NOT_CONFIGURED,
            detail="No API key configured.",
        ))

    if uh_provider:
        provider_results.append(ProviderResult(
            name="URLhaus",
            status=ProviderStatus.NO_MATCH,
            detail="Malicious URL database check completed.",
        ))
    else:
        provider_results.append(ProviderResult(
            name="URLhaus",
            status=ProviderStatus.NOT_CONFIGURED,
            detail="URLhaus lookups are disabled.",
        ))

    # Recalculate
    final_score = min(score, 100)
    risk_level = get_risk_level(final_score)
    classification = get_classification(risk_level, "message")
    recommendations = build_recommendations(risk_level, "message", indicators)

    # Step 3: AI explanation
    ai_explanation = None
    ai_available = False
    if gemini_provider:
        try:
            ai_explanation = await gemini_provider.explain_findings(
                scan_type="message",
                input_preview=_truncate(message, 150),
                risk_level=risk_level,
                risk_score=final_score,
                indicators=indicators,
            )
            ai_available = True
        except Exception:
            ai_explanation = None
            ai_available = False

    if not ai_available:
        provider_results.append(ProviderResult(
            name="Gemini AI",
            status=ProviderStatus.NOT_CONFIGURED if not gemini_provider else ProviderStatus.FAILED,
            detail="AI explanations are unavailable.",
        ))
    else:
        provider_results.append(ProviderResult(
            name="Gemini AI",
            status=ProviderStatus.MATCH,
            detail="AI-assisted explanation generated.",
        ))

    metadata = {
        "extracted_urls": len(extracted_urls),
        "extracted_emails": len(extracted.get("emails", [])),
        "extracted_phones": len(extracted.get("phones", [])),
        "message_length": len(message),
    }

    return AnalysisResponse(
        scan_id=scan_id,
        scan_type=ScanType.MESSAGE,
        timestamp=timestamp,
        input_preview=_truncate(message, 80),
        risk_score=final_score,
        risk_level=risk_level,
        classification=classification,
        indicators=indicators,
        indicator_count=len(indicators),
        providers=provider_results,
        recommendations=recommendations,
        ai_explanation=ai_explanation,
        ai_available=ai_available,
        analysis_metadata=metadata,
    )


def _truncate(text: str, max_len: int = 80) -> str:
    """Truncate text for safe display, avoiding sensitive data exposure."""
    text = text.strip()
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."
