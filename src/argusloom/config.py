"""Application configuration loaded from environment variables and .env files."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings for ArgusLoom.

    The project defaults intentionally favour deterministic offline behaviour:
    the mock adapters are enabled unless users explicitly opt out.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "argusloom"
    argus_use_mock_llm: bool = Field(default=True)
    argus_use_mock_nvd: bool = Field(default=True)
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    log_level: str = Field(default="INFO")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a lazily cached settings instance."""

    return Settings()
