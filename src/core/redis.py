from typing import Optional
import redis.asyncio as aioredis
from src.core.config import settings

redis_client: Optional[aioredis.Redis] = None


async def init_redis_pool() -> aioredis.Redis:
    """Inicializa pool global de conexão assíncrona com o Redis."""
    global redis_client
    redis_client = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
        max_connections=50,
    )
    return redis_client


async def close_redis_pool() -> None:
    """Encerra a conexão com o Redis de forma graciosa."""
    global redis_client
    if redis_client is not None:
        await redis_client.close()
        redis_client = None


def get_redis() -> Optional[aioredis.Redis]:
    """Retorna o cliente Redis ativo."""
    return redis_client
