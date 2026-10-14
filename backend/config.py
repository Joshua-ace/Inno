"""
DaddyDefender configuration management.
Loads settings from environment variables with safe defaults.
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # API Keys (all optional)
    gemini_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    urlhaus_enabled: bool = True

    # Server
    backend_host: str = "127.0.0.1"
    backend_port: int = 8000
    cors_origins: str = "http://localhost:5500,http://127.0.0.1:5500,http://localhost:8000"

    # Database
    database_path: str = "daddydefender.db"

    # Rate limiting
    rate_limit: str = "30/minute"

    # Provider timeouts (seconds)
    provider_timeout: int = 10
    gemini_timeout: int = 15

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def gemini_configured(self) -> bool:
        return bool(self.gemini_api_key and self.gemini_api_key.strip())

    @property
    def virustotal_configured(self) -> bool:
        return bool(self.virustotal_api_key and self.virustotal_api_key.strip())

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
