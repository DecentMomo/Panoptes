from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://panoptes:panoptes@localhost:5432/panoptes"
    secret_key: str = "change-me"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5-coder:7b"
    # Accepts a JSON list (as in .env.example) or a single origin string.
    cors_origins: list[str] = ["http://localhost:5173"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str) and not value.startswith("["):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


settings = Settings()
