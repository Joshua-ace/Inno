"""
Health check endpoint.
GET /api/health - System health and provider status
"""

from fastapi import APIRouter, Request
from models import HealthResponse

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check(request: Request):
    """
    Returns application health status and availability of each provider.
    """
    provider_status = {}

    # Check each provider
    providers = getattr(request.app.state, "providers", {})
    for name, provider in providers.items():
        try:
            status = await provider.health_check()
            provider_status[name] = status
        except Exception:
            provider_status[name] = "error"

    # Check Gemini
    gemini = getattr(request.app.state, "gemini", None)
    if gemini:
        try:
            provider_status["gemini"] = await gemini.health_check()
        except Exception:
            provider_status["gemini"] = "error"
    else:
        provider_status["gemini"] = "not_configured"

    return HealthResponse(
        status="healthy",
        version="1.0.0",
        providers=provider_status,
    )
