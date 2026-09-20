from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_PATH = BASE_DIR/".env"

class Settings(BaseSettings):
    APP_NAME: str = "Basecheck"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    DATABASE_URL: str

    model_config = SettingsConfigDict(
        env_file=ENV_PATH,
        env_file_encoding="utf-8",
        extra="ignore",
    )

settings = Settings()