from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = Field(default='PhishPhage AI API', alias='APP_NAME')
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

    # Dataset curation is deliberately disabled by default and is kept out of
    # the production inference configuration. Secret fields are never exposed
    # through a response model or diagnostic payload.
    dataset_review_enabled: bool = Field(default=False, alias='DATASET_REVIEW_ENABLED')
    dataset_review_local_only: bool = Field(default=True, alias='DATASET_REVIEW_LOCAL_ONLY')
    dataset_review_admin_token: str | None = Field(default=None, alias='DATASET_REVIEW_ADMIN_TOKEN', repr=False)
    gemini_review_enabled: bool = Field(default=False, alias='GEMINI_REVIEW_ENABLED')
    gemini_api_key: str | None = Field(default=None, alias='GEMINI_API_KEY', repr=False)
    google_api_key: str | None = Field(default=None, alias='GOOGLE_API_KEY', repr=False)
    gemini_model: str | None = Field(default=None, alias='GEMINI_MODEL')
    gemini_request_timeout_seconds: int = Field(default=45, ge=1, le=120, alias='GEMINI_REQUEST_TIMEOUT_SECONDS')
    gemini_max_retries: int = Field(default=1, ge=0, le=3, alias='GEMINI_MAX_RETRIES')
    gemini_max_concurrent_requests: int = Field(default=1, ge=1, le=4, alias='GEMINI_MAX_CONCURRENT_REQUESTS')
    gemini_session_review_limit: int = Field(default=5, ge=1, le=25, alias='GEMINI_SESSION_REVIEW_LIMIT')
    gemini_daily_review_limit: int = Field(default=10, ge=1, le=100, alias='GEMINI_DAILY_REVIEW_LIMIT')
    gemini_batch_enabled: bool = Field(default=False, alias='GEMINI_BATCH_ENABLED')
    gemini_cache_enabled: bool = Field(default=False, alias='GEMINI_CACHE_ENABLED')
    gemini_sanitized_subject_max_chars: int = Field(default=300, ge=1, le=300, alias='GEMINI_SANITIZED_SUBJECT_MAX_CHARS')
    gemini_sanitized_body_max_chars: int = Field(default=8000, ge=1, le=8000, alias='GEMINI_SANITIZED_BODY_MAX_CHARS')
    gemini_sanitized_payload_max_bytes: int = Field(default=16384, ge=1024, le=16384, alias='GEMINI_SANITIZED_PAYLOAD_MAX_BYTES')
    gemini_prompt_version: str = Field(default='gemini-review-v1', alias='GEMINI_PROMPT_VERSION')
    dataset_review_storage_path: str = Field(
        default='services/ml/evaluation/private/review_workspace.sqlite3',
        alias='DATASET_REVIEW_STORAGE_PATH',
    )

    @model_validator(mode='after')
    def validate_review_secret_contract(self) -> 'Settings':
        if self.gemini_api_key and self.google_api_key:
            raise ValueError('Conflicting provider API key configuration.')
        if self.dataset_review_admin_token and self.gemini_api_key and self.dataset_review_admin_token == self.gemini_api_key:
            raise ValueError('Dataset review admin token must be separate from the provider API key.')
        if self.gemini_batch_enabled:
            raise ValueError('Gemini batch review is disabled for this phase.')
        return self

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
