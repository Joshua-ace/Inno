"""
Abstract base interface for all threat intelligence providers.
Every provider must implement this interface so it can be
enabled, disabled, or replaced independently.
"""

from abc import ABC, abstractmethod
from models import ProviderResult


class BaseThreatProvider(ABC):
    """Base class for threat intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name."""
        ...

    @property
    @abstractmethod
    def configured(self) -> bool:
        """Whether the provider has valid configuration (API keys, etc.)."""
        ...

    @abstractmethod
    async def check_url(self, url: str) -> ProviderResult:
        """
        Check a URL against this provider's intelligence.
        Must return a ProviderResult with one of:
          - MATCH: confirmed malicious
          - SUSPICIOUS: partial evidence
          - NO_MATCH: no known match returned
          - UNAVAILABLE: lookup could not be performed
          - FAILED: lookup attempted but errored
          - NOT_CONFIGURED: provider not set up
        """
        ...

    async def health_check(self) -> str:
        """Return a status string for the health endpoint."""
        if not self.configured:
            return "not_configured"
        return "configured"
