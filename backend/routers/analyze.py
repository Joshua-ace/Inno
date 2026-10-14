"""
Analysis API endpoints.
POST /api/analyze/url     - Analyze a URL
POST /api/analyze/message - Analyze a message
"""

import json
import logging
from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse

from models import (
    URLAnalysisRequest, MessageAnalysisRequest,
    AnalysisResponse, ErrorResponse,
)
from scoring.engine import run_url_analysis, run_message_analysis
from database import get_db

logger = logging.getLogger("daddydefender.analyze")

router = APIRouter(prefix="/api/analyze", tags=["analysis"])


@router.post(
    "/url",
    response_model=AnalysisResponse,
    responses={
        400: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def analyze_url(
    body: URLAnalysisRequest,
    request: Request,
):
    """
    Analyze a URL for phishing, fraud, and malicious indicators.
    Returns a scored assessment with evidence-based findings.
    """
    try:
        providers = getattr(request.app.state, "providers", {})
        gemini = getattr(request.app.state, "gemini", None)

        result = await run_url_analysis(
            raw_url=body.url,
            providers=providers,
            gemini_provider=gemini,
        )

        # Persist to database
        await _save_scan(request, result)

        return result

    except Exception as e:
        logger.error(f"URL analysis error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Analysis failed", "detail": "An internal error occurred during URL analysis."},
        )


@router.post(
    "/message",
    response_model=AnalysisResponse,
    responses={
        400: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def analyze_message(
    body: MessageAnalysisRequest,
    request: Request,
):
    """
    Analyze a message for phishing, scam, and social engineering indicators.
    Returns a scored assessment with evidence-based findings.
    """
    try:
        providers = getattr(request.app.state, "providers", {})
        gemini = getattr(request.app.state, "gemini", None)

        result = await run_message_analysis(
            message=body.message,
            providers=providers,
            gemini_provider=gemini,
        )

        # Persist to database
        await _save_scan(request, result)

        return result

    except Exception as e:
        logger.error(f"Message analysis error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Analysis failed", "detail": "An internal error occurred during message analysis."},
        )


async def _save_scan(request: Request, result: AnalysisResponse):
    """Persist scan result to database."""
    try:
        import aiosqlite
        from database import DB_PATH

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """INSERT INTO scans
                   (id, scan_type, created_at, risk_score, risk_level,
                    classification, input_preview, findings,
                    provider_status, recommendations, ai_explanation)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.scan_id,
                    result.scan_type.value,
                    result.timestamp,
                    result.risk_score,
                    result.risk_level.value,
                    result.classification,
                    result.input_preview,
                    json.dumps([ind.model_dump() for ind in result.indicators]),
                    json.dumps([pr.model_dump() for pr in result.providers]),
                    json.dumps(result.recommendations),
                    result.ai_explanation,
                ),
            )
            await db.commit()
    except Exception as e:
        logger.error(f"Failed to save scan: {e}")
