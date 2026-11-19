import secrets

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    environment: str = "development"
    database_url: str = "postgresql+psycopg://vulnscope:vulnscope@localhost:5432/vulnscope"
    max_code_size_bytes: int = 200_000
    semgrep_timeout_seconds: int = 30
    bandit_timeout_seconds: int = 15
    eslint_timeout_seconds: int = 30
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24 * 7
    gemini_api_key: SecretStr = SecretStr("")
    gemini_model: str = "gemini-3.5-flash-lite"
    teacher_emails: str = ""
    cors_origins: str = "http://localhost:3000"
    cookie_secure: bool = False
    rate_limit_enabled: bool = True
    trust_forwarded_for: bool = False

    class Config:
        env_file = ".env"
        extra = "ignore"

    @model_validator(mode="after")
    def check_jwt_secret(self):
        production = self.environment.lower() == "production"
        if not self.jwt_secret_key:
            if production:
                raise ValueError("JWT_SECRET_KEY must be set when ENVIRONMENT=production")
            # Development only: a random key per process. Logins reset on restart.
            self.jwt_secret_key = secrets.token_urlsafe(32)
        elif production and len(self.jwt_secret_key.encode("utf-8")) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 bytes in production")
        return self


settings = Settings()