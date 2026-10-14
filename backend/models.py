"""
Pydantic request and response schemas for all API endpoints.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional
from enum import Enum


# ── Enums ──────────────────────────────────────────────

class ScanType(str, Enum):
    URL = "url"
    MESSAGE = "message"


class RiskLevel(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class ProviderStatus(str, Enum):
    MATCH = "match"
    SUSPICIOUS = "suspicious"
    NO_MATCH = "no_match"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    NOT_CONFIGURED = "not_configured"


# ── Request Models ─────────────────────────────────────

class URLAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096, description="URL to analyze")

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        return v


class MessageAnalysisRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000, description="Message text to analyze")

    @field_validator("message")
    @classmethod
    def message_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Message cannot be empty")
        return v


# ── Response Models ────────────────────────────────────

class Indicator(BaseModel):
    severity: Severity
    name: str
    detail: str
    points: int = Field(description="Points this indicator contributed to the total score")
    source: str = Field(default="local", description="Source: local, virustotal, urlhaus, gemini")


class ProviderResult(BaseModel):
    name: str
    status: ProviderStatus
    detail: Optional[str] = None
    data: Optional[dict] = None


class AnalysisResponse(BaseModel):
    scan_id: str
    scan_type: ScanType
    timestamp: str
    input_preview: str = Field(description="Truncated/redacted version of the submitted input")

    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    classification: str

    indicators: list[Indicator]
    indicator_count: int

    providers: list[ProviderResult]
    recommendations: list[str]

    ai_explanation: Optional[str] = None
    ai_available: bool = False

    analysis_metadata: dict = Field(default_factory=dict, description="Hostname, domain, etc.")

    limitations: str = Field(
        default="This assessment is based on pattern analysis and available threat intelligence. "
                "It is not a guarantee of safety or maliciousness. A low score does not prove a URL "
                "or message is safe. Always verify through official channels."
    )


class ScanSummary(BaseModel):
    scan_id: str
    scan_type: ScanType
    timestamp: str
    input_preview: str
    risk_score: int
    risk_level: RiskLevel
    classification: str


class ScanListResponse(BaseModel):
    scans: list[ScanSummary]
    total: int


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    providers: dict[str, str]


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
