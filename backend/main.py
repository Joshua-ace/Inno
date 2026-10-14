"""
DaddyDefender Backend: FastAPI Application Entry Point

Serves the API and the frontend static files.
Run with: python main.py
"""

import os
import sys
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings
from database import init_db
from routers import analyze, scans, health
from providers.virustotal import VirusTotalProvider
from providers.urlhaus import URLhausProvider
from providers.gemini_provider import GeminiProvider

# ── Logging ────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("daddydefender")


# ── App Lifespan ───────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and providers on startup."""
    # Database
    logger.info("Initializing database...")
    await init_db()

    # Providers
    logger.info("Initializing threat intelligence providers...")
    providers = {}

    vt = VirusTotalProvider()
    if vt.configured:
        providers["virustotal"] = vt
        logger.info("  VirusTotal: configured")
    else:
        logger.info("  VirusTotal: not configured (no API key)")

    uh = URLhausProvider()
    if uh.configured:
        providers["urlhaus"] = uh
        logger.info("  URLhaus: enabled")
    else:
        logger.info("  URLhaus: disabled")

    app.state.providers = providers

    # Gemini
    gemini = GeminiProvider()
    if gemini.available:
        app.state.gemini = gemini
        logger.info("  Gemini AI: configured")
    else:
        app.state.gemini = None
        logger.info("  Gemini AI: not configured (no API key)")

    logger.info("DaddyDefender backend ready.")

    yield

    logger.info("DaddyDefender shutting down.")


# ── FastAPI App ────────────────────────────────────────

app = FastAPI(
    title="DaddyDefender API",
    description="AI-Powered Digital Threat Detection API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ── Rate Limiting ──────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ───────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# ── Request Size Limit Middleware ──────────────────────

MAX_BODY_SIZE = 50 * 1024  # 50 KB


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    """Reject requests with bodies larger than MAX_BODY_SIZE."""
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_BODY_SIZE:
            return JSONResponse(
                status_code=413,
                content={"error": "Request body too large", "detail": f"Maximum size is {MAX_BODY_SIZE} bytes."},
            )
    return await call_next(request)


# ── API Routes ─────────────────────────────────────────

app.include_router(analyze.router)
app.include_router(scans.router)
app.include_router(health.router)

# ── Serve Frontend Static Files ────────────────────────

# The frontend files are in the parent directory (project root)
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/privacy-policy")
@app.get("/privacy-policy.html")
async def serve_privacy():
    return FileResponse(os.path.join(FRONTEND_DIR, "privacy-policy.html"))


@app.get("/terms")
@app.get("/terms.html")
async def serve_terms():
    return FileResponse(os.path.join(FRONTEND_DIR, "terms.html"))


# Serve static assets (CSS, JS, SVG)
@app.get("/{filename:path}")
async def serve_static(filename: str):
    filepath = os.path.join(FRONTEND_DIR, filename)
    if os.path.isfile(filepath) and not filename.startswith(("backend", ".env", ".git")):
        return FileResponse(filepath)
    return JSONResponse(status_code=404, content={"error": "Not found"})


# ── Entry Point ────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    logger.info(f"Starting DaddyDefender on http://{settings.backend_host}:{settings.backend_port}")
    uvicorn.run(
        "main:app",
        host=settings.backend_host,
        port=settings.backend_port,
        reload=True,
        log_level="info",
    )
