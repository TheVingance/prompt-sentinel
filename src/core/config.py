from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Aplicação
    PROJECT_NAME: str = "PromptSentinel AI Firewall"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Chave de API do Gateway
    SENTINEL_API_KEY: str = "sentinel-default-local-key"

    # Provedor upstream (OpenAI, Ollama, etc.)
    TARGET_LLM_BASE_URL: str = "https://api.openai.com/v1"
    TARGET_LLM_API_KEY: str = ""

    # PostgreSQL & pgvector
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "sentinel"
    POSTGRES_PASSWORD: str = "sentinel_secure_pass"
    POSTGRES_DB: str = "sentinel_db"

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""

    # Parâmetros de Segurança
    SIMILARITY_THRESHOLD: float = 0.82
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60

    # Cache Semântico & FinOps Engine
    SEMANTIC_CACHE_ENABLED: bool = True
    CACHE_SIMILARITY_THRESHOLD: float = 0.95
    CACHE_TTL_SECONDS: int = 3600

    @computed_field
    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @computed_field
    @property
    def redis_url(self) -> str:
        auth = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"redis://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/0"


settings = Settings()
