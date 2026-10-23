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

    class Config:
        env_file = ".env"


settings = Settings()