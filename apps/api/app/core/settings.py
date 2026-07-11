from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = Field(default='phishshield-api', alias='APP_NAME')
    app_version: str = Field(default='0.1.0', alias='APP_VERSION')
    environment: str = Field(default='development', alias='ENVIRONMENT')
    api_v1_prefix: str = Field(default='/api/v1', alias='API_V1_PREFIX')
    cors_origins: list[str] = Field(default_factory=lambda: ['http://localhost:3000'], alias='CORS_ORIGINS')
    log_level: str = Field(default='INFO', alias='LOG_LEVEL')
    ml_model_path: str = Field(
        default='services/ml/models/phishshield_model.joblib',
        alias='ML_MODEL_PATH',
    )
    ml_required: bool = Field(default=False, alias='ML_REQUIRED')
    firebase_project_id: str | None = Field(default=None, alias='FIREBASE_PROJECT_ID')
    firebase_client_email: str | None = Field(default=None, alias='FIREBASE_CLIENT_EMAIL')
    firebase_private_key: str | None = Field(default=None, alias='FIREBASE_PRIVATE_KEY')

    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        extra='ignore',
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
