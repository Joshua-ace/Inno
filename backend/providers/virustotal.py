"""
VirusTotal API integration.
Docs: https://docs.virustotal.com/reference/url-info

Free tier limits: 4 requests/minute, 500 requests/day.
"""

import hashlib
import base64
import logging
import httpx

from providers.base import BaseThreatProvider
from models import ProviderResult, ProviderStatus
from config import settings

logger = logging.getLogger("daddydefender.virustotal")

VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(BaseThreatProvider):
    """VirusTotal URL reputation lookup."""

    def __init__(self):
        self._api_key = settings.virustotal_api_key or ""
        self._timeout = settings.provider_timeout

    @property
    def name(self) -> str:
        return "VirusTotal"

    @property
    def configured(self) -> bool:
        return bool(self._api_key.strip())

    async def check_url(self, url: str) -> ProviderResult:
        if not self.configured:
            return ProviderResult(
                name=self.name,
                status=ProviderStatus.NOT_CONFIGURED,
                detail="No API key configured. Add VIRUSTOTAL_API_KEY to .env.",
            )

        try:
            # VirusTotal uses base64-encoded URL (without padding) as the ID
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(
                    f"{VT_API_BASE}/urls/{url_id}",
                    headers={"x-apikey": self._api_key},
                )

            if response.status_code == 404:
                # URL not yet analyzed by VirusTotal
                return ProviderResult(
                    name=self.name,
                    status=ProviderStatus.NO_MATCH,
                    detail="URL has not been previously analyzed by VirusTotal.",
                )

            if response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
                return ProviderResult(
                    name=self.name,
                    status=ProviderStatus.UNAVAILABLE,
                    detail="VirusTotal rate limit exceeded. Try again later.",
                )

            if response.status_code == 401:
                logger.error("VirusTotal API key is invalid")
                return ProviderResult(
                    name=self.name,
                    status=ProviderStatus.FAILED,
                    detail="VirusTotal API key is invalid.",
                )

            if response.status_code != 200:
                logger.error(f"VirusTotal unexpected status: {response.status_code}")
                return ProviderResult(
                    name=self.name,
                    status=ProviderStatus.FAILED,
                    detail=f"VirusTotal returned status {response.status_code}.",
                )

            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            result_data = {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_vendors": total,
            }

            if malicious >= 3:
                return ProviderResult(
                    name=self.name,
                    status=ProviderStatus.MATCH,
                    detail=f"{malicious} out of {total} security vendors flagged "
                           f"this URL as malicious.",
                    data=result_data,
                )
            elif malicious >= 1 or suspicious >= 2:
                return ProviderResult(
                    name=self.name,
                    status=ProviderStatus.SUSPICIOUS,
                    detail=f"{malicious} malicious and {suspicious} suspicious "
                           f"detections out of {total} vendors.",
                    data=result_data,
                )
            else:
                return ProviderResult(
                    name=self.name,
                    status=ProviderStatus.NO_MATCH,
                    detail=f"No malicious detections from {total} vendors. "
                           "This does not guarantee safety.",
                    data=result_data,
                )

        except httpx.TimeoutException:
            logger.warning("VirusTotal request timed out")
            return ProviderResult(
                name=self.name,
                status=ProviderStatus.UNAVAILABLE,
                detail="VirusTotal request timed out.",
            )
        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
            return ProviderResult(
                name=self.name,
                status=ProviderStatus.FAILED,
                detail="VirusTotal lookup failed due to an unexpected error.",
            )

    async def health_check(self) -> str:
        if not self.configured:
            return "not_configured"
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(
                    f"{VT_API_BASE}/urls",
                    headers={"x-apikey": self._api_key},
                )
            if response.status_code in (200, 400):
                return "healthy"
            elif response.status_code == 401:
                return "invalid_key"
            elif response.status_code == 429:
                return "rate_limited"
            return f"error_{response.status_code}"
        except Exception:
            return "unreachable"
