from __future__ import annotations

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "Threat Intelligence Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR / 'data' / 'threat_intel.db'}"

    JWT_SECRET_KEY: str = "change-me-in-production-use-openssl-rand-hex-32"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    REDIS_URL: str = "redis://localhost:6379/0"

    VIRUSTOTAL_API_KEY: str = ""
    SHODAN_API_KEY: str = ""

    WHOIS_RATE_LIMIT: int = 2
    ENRICHMENT_CONCURRENCY: int = 10

    CORS_ORIGINS: list[str] = ["*"]

    FEEDS_PATH: str = str(BASE_DIR / "data" / "feeds.json")


settings = Settings()
