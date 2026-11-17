from pydantic import SecretStr
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://vulnscope:vulnscope@localhost:5432/vulnscope"
    max_code_size_bytes: int = 200_000
    semgrep_timeout_seconds: int = 30
    bandit_timeout_seconds: int = 15
    eslint_timeout_seconds: int = 30
    jwt_secret_key: str = "dev-secret-change-me"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24 * 7
    gemini_api_key: SecretStr = SecretStr("")
    gemini_model: str = "gemini-3.5-flash-lite"
    teacher_emails: str = ""

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()