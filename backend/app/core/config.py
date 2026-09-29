from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://panoptes:panoptes@localhost:5432/panoptes"
    # Placeholder only. HMAC-SHA256 wants at least 32 bytes, and startup warns on "change-me".
    secret_key: str = "change-me-please-use-a-long-random-secret-key"
    access_token_expire_minutes: int = 60
    # Off for local http. Turn on only behind HTTPS, or the browser will drop the cookies.
    cookie_secure: bool = False
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5-coder:7b"
    # Accepts a JSON list (as in .env.example) or a single origin string.
    cors_origins: list[str] = ["http://localhost:5173"]
    # Empty means the system temp directory. Uploaded code is deleted after the scan.
    scan_workdir: str = ""
    max_upload_bytes: int = 20 * 1024 * 1024
    max_uncompressed_bytes: int = 100 * 1024 * 1024
    max_file_count: int = 5000
    bandit_timeout_seconds: int = 120
    snippet_context_lines: int = 7
    scan_rate_limit: int = 5
    scan_rate_window_seconds: int = 60
    # The IP bucket is tighter on purpose: one host is blocked before it can
    # exhaust a victim's email bucket and lock them out.
    login_rate_limit_ip: int = 10
    login_rate_limit_email: int = 20
    login_rate_window_seconds: int = 60

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str) and not value.startswith("["):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


settings = Settings()
