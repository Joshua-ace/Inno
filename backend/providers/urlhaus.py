"""
URLhaus API integration.
Docs: https://urlhaus-api.abuse.ch/

URLhaus is a free service by abuse.ch. No API key required.
"""

import logging
import hashlib
from urllib.parse import urlparse
import httpx

from providers.base import BaseThreatProvider
from models import ProviderResult, ProviderStatus
from config import settings

logger = logging.getLogger("daddydefender.urlhaus")

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"


class URLhausProvider(BaseThreatProvider):
    """URLhaus malicious URL database lookup."""

    def __init__(self):
        self._enabled = settings.urlhaus_enabled
        self._timeout = settings.provider_timeout

    @property
    def name(self) -> str:
        return "URLhaus"

    @property
    def configured(self) -> bool:
        return self._enabled

    async def check_url(self, url: str) -> ProviderResult:
        if not self.configured:
            return ProviderResult(
                name=self.name,
                status=ProviderStatus.NOT_CONFIGURED,
                detail="URLhaus lookups are disabled.",
            )

        try:
            # Normalize the URL for lookup
            normalized = self._normalize_url(url)

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{URLHAUS_API}/url/",
                    data={"url": normalized},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

            if response.status_code != 200:
                logger.error(f"URLhaus unexpected status: {response.status_code}")
                return ProviderResult(
                    name=self.name,
                    status=ProviderStatus.FAILED,
                    detail=f"URLhaus returned status {response.status_code}.",
                )

            data = response.json()
            query_status = data.get("query_status", "")

            if query_status == "no_results":
                return ProviderResult(
                    name=self.name,
                    status=ProviderStatus.NO_MATCH,
                    detail="URL not found in URLhaus database. This does not guarantee safety.",
                )

            if query_status == "ok":
                threat_type = data.get("threat", "unknown")
                url_status = data.get("url_status", "unknown")
                tags = data.get("tags") or []
                date_added = data.get("date_added", "unknown")

                result_data = {
                    "threat": threat_type,
                    "url_status": url_status,
                    "tags": tags[:5] if tags else [],
                    "date_added": date_added,
                }

                detail_parts = [f"Listed in URLhaus as \"{threat_type}\""]
                if url_status:
                    detail_parts.append(f"status: {url_status}")
                if tags:
                    detail_parts.append(f"tags: {', '.join(tags[:3])}")

                return ProviderResult(
                    name=self.name,
                    status=ProviderStatus.MATCH,
                    detail=". ".join(detail_parts) + ".",
                    data=result_data,
                )

            # Unknown query_status
            return ProviderResult(
                name=self.name,
                status=ProviderStatus.FAILED,
                detail=f"Unexpected URLhaus response status: {query_status}.",
            )

        except httpx.TimeoutException:
            logger.warning("URLhaus request timed out")
            return ProviderResult(
                name=self.name,
                status=ProviderStatus.UNAVAILABLE,
                detail="URLhaus request timed out.",
            )
        except Exception as e:
            logger.error(f"URLhaus error: {e}")
            return ProviderResult(
                name=self.name,
                status=ProviderStatus.FAILED,
                detail="URLhaus lookup failed due to an unexpected error.",
            )

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for URLhaus lookup."""
        url = url.strip()
        # Ensure scheme
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        # Remove trailing slash for consistency
        parsed = urlparse(url)
        if parsed.path == "/" and not parsed.query and not parsed.fragment:
            url = url.rstrip("/")
        return url

    async def health_check(self) -> str:
        if not self.configured:
            return "disabled"
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.post(
                    f"{URLHAUS_API}/url/",
                    data={"url": "https://example.com"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            if response.status_code == 200:
                return "healthy"
            return f"error_{response.status_code}"
        except Exception:
            return "unreachable"
