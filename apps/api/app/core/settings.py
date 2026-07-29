from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = Field(default='PhishShield AI API', alias='APP_NAME')
    app_version: str = Field(default='1.0.0-rc1', alias='APP_VERSION')
    environment: str = Field(default='development', alias='ENVIRONMENT')
    api_v1_prefix: str = Field(default='/api/v1', alias='API_V1_PREFIX')
    cors_origins: list[str] = Field(default_factory=lambda: ['http://localhost:3000'], alias='CORS_ORIGINS')
    log_level: str = Field(default='INFO', alias='LOG_LEVEL')
    # Uvicorn's access logger is useful during development. In production the
    # structured application request event is the source of truth, so the
    # duplicate Uvicorn stream can be disabled explicitly (or by environment
    # default when this value is omitted).
    uvicorn_access_log: bool | None = Field(default=None, alias='UVICORN_ACCESS_LOG')
    max_request_bytes: int = Field(default=2_200_000, ge=1024, le=10_000_000, alias='MAX_REQUEST_BYTES')
    rate_limit_enabled: bool = Field(default=True, alias='RATE_LIMIT_ENABLED')
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600, alias='RATE_LIMIT_WINDOW_SECONDS')
    rate_limit_health: int = Field(default=300, ge=1, le=10000, alias='RATE_LIMIT_HEALTH')
    rate_limit_parser: int = Field(default=60, ge=1, le=10000, alias='RATE_LIMIT_PARSER')
    rate_limit_analysis: int = Field(default=120, ge=1, le=10000, alias='RATE_LIMIT_ANALYSIS')
    trusted_proxy_ips: list[str] = Field(default_factory=list, alias='TRUSTED_PROXY_IPS')
    ml_registry_path: str = Field(
        default='services/ml/models/registry.json',
        alias='ML_REGISTRY_PATH',
    )
    ml_model_id: str = Field(
        default='phase-c-logistic-regression-v1',
        alias='ML_MODEL_ID',
    )
    ml_artifact_path: str | None = Field(default=None, alias='ML_ARTIFACT_PATH')
    ml_required: bool = Field(default=False, alias='ML_REQUIRED')
    ml_marginal_alert_band: float = Field(
        default=0.08,
        ge=0.0,
        le=0.25,
        alias='ML_MARGINAL_ALERT_BAND',
    )
    firebase_project_id: str | None = Field(default=None, alias='FIREBASE_PROJECT_ID')
    firebase_client_email: str | None = Field(default=None, alias='FIREBASE_CLIENT_EMAIL')
    firebase_private_key: str | None = Field(default=None, alias='FIREBASE_PRIVATE_KEY')

    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        extra='ignore',
    )

    @field_validator('cors_origins', 'trusted_proxy_ips', mode='before')
    @classmethod
    def parse_csv_settings(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(',') if item.strip()]
        return value

    @field_validator('cors_origins')
    @classmethod
    def normalize_cors_origins(cls, value: list[str], info) -> list[str]:
        normalized = list(dict.fromkeys(item.rstrip('/') for item in value))
        if '*' in normalized:
            raise ValueError('CORS_ORIGINS must not contain wildcard origins')
        if str(info.data.get('environment', 'development')).lower() == 'production' and any(
            origin.startswith(('http://localhost', 'http://127.0.0.1')) for origin in normalized
        ):
            raise ValueError('localhost origins are development-only')
        return normalized

    @property
    def uvicorn_access_log_enabled(self) -> bool:
        """Return the effective Uvicorn access-log policy for this environment."""
        if self.uvicorn_access_log is not None:
            return self.uvicorn_access_log
        return self.environment.lower() != 'production'


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
