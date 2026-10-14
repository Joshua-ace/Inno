"""
Integration tests for FastAPI endpoints:
/api/health, /api/analyze/url, /api/analyze/message, /api/scans, /api/scans/{id}.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from main import app
from database import init_db


import pytest_asyncio


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    """Ensure database schema is ready before API tests run."""
    await init_db()
    # Initialize app providers state if not set by lifespan in test runner
    if not hasattr(app.state, "providers"):
        app.state.providers = {}
    if not hasattr(app.state, "gemini"):
        app.state.gemini = None


@pytest.mark.asyncio
async def test_health_endpoint():
    """GET /api/health must return 200 with system status and provider dictionary."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "providers" in data


@pytest.mark.asyncio
async def test_analyze_url_valid():
    """POST /api/analyze/url should return 200 with structured analysis."""
    payload = {"url": "http://paypa1-fake.tk/login"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/analyze/url", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["scan_type"] == "url"
        assert data["risk_score"] > 0
        assert "indicators" in data
        assert "recommendations" in data


@pytest.mark.asyncio
async def test_analyze_url_empty_validation():
    """POST /api/analyze/url with empty string must return 422 validation error."""
    payload = {"url": "   "}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/analyze/url", json=payload)
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_analyze_message_valid():
    """POST /api/analyze/message should return 200 with structured analysis."""
    payload = {
        "message": "URGENT: Your account has been suspended. Confirm your password now at http://fake-login.xyz"
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/analyze/message", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["scan_type"] == "message"
        assert data["risk_score"] >= 40


@pytest.mark.asyncio
async def test_scans_history_and_deletion():
    """Verify scanning persists to database, appears in /api/scans, and can be retrieved and deleted."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create a scan
        scan_res = await client.post("/api/analyze/url", json={"url": "https://test-example-site.com"})
        assert scan_res.status_code == 200
        scan_id = scan_res.json()["scan_id"]

        # List scans
        list_res = await client.get("/api/scans")
        assert list_res.status_code == 200
        list_data = list_res.json()
        assert list_data["total"] >= 1
        assert any(s["scan_id"] == scan_id for s in list_data["scans"])

        # Get specific scan
        get_res = await client.get(f"/api/scans/{scan_id}")
        assert get_res.status_code == 200
        assert get_res.json()["scan_id"] == scan_id

        # Delete scan
        del_res = await client.delete(f"/api/scans/{scan_id}")
        assert del_res.status_code == 200

        # Verify 404 after deletion
        get_after_del = await client.get(f"/api/scans/{scan_id}")
        assert get_after_del.status_code == 404
