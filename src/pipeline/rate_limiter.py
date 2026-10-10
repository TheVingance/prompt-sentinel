import time
import uuid
from typing import NamedTuple

import redis.asyncio as aioredis
from fastapi import HTTPException, Request, status

from src.core.config import settings
from src.core.redis import get_redis


class RateLimitResult(NamedTuple):
    allowed: bool
    limit: int
    remaining: int
    reset_seconds: int


class SlidingWindowRateLimiter:
    """Implementa o algoritmo de limitação de taxa por Janela Deslizante (Sliding Window)

    utilizando Redis Sorted Sets (ZSET) para distribuição atômica entre réplicas.
    """

    def __init__(self, limit: int = 60, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds

    async def is_allowed(
        self,
        identifier: str,
        redis_client: aioredis.Redis | None = None,
    ) -> RateLimitResult:
        """Verifica e consome uma cota na janela deslizante."""
        if redis_client is None:
            redis_client = get_redis()

        # Fallback gracioso se Redis estiver indisponível em testes/desenvolvimento
        if redis_client is None:
            return RateLimitResult(
                allowed=True,
                limit=self.limit,
                remaining=self.limit - 1,
                reset_seconds=0,
            )

        now = time.time()
        window_start = now - self.window_seconds
        key = f"rate_limit:{identifier}"

        try:
            # Pipeline atômico no Redis
            async with redis_client.pipeline(transaction=True) as pipe:
                # 1. Remove requisições que caíram fora da janela de tempo atual
                pipe.zremrangebyscore(key, 0, window_start)
                # 2. Conta quantas requisições restam na janela
                pipe.zcard(key)
                # 3. Adiciona a requisição atual com score = timestamp
                member_id = f"{now}:{uuid.uuid4().hex[:6]}"
                pipe.zadd(key, {member_id: now})
                # 4. Atualiza o TTL da chave para expirar junto com a janela
                pipe.expire(key, self.window_seconds + 1)
                results = await pipe.execute()

            current_count = results[1]

            if current_count >= self.limit:
                # Remove a requisição recém-inserida pois o limite foi violado
                await redis_client.zrem(key, member_id)
                return RateLimitResult(
                    allowed=False,
                    limit=self.limit,
                    remaining=0,
                    reset_seconds=int(self.window_seconds),
                )

            remaining = max(0, self.limit - (current_count + 1))
            return RateLimitResult(
                allowed=True,
                limit=self.limit,
                remaining=remaining,
                reset_seconds=int(self.window_seconds),
            )

        except Exception as exc:
            # Em caso de erro de rede temporário no Redis, loga e opera em fail-open
            print(f"[RateLimiter Warning] Falha na checagem do Redis: {exc}")
            return RateLimitResult(
                allowed=True,
                limit=self.limit,
                remaining=self.limit - 1,
                reset_seconds=0,
            )


# Instância global configurada a partir das variáveis de ambiente
rate_limiter = SlidingWindowRateLimiter(
    limit=settings.RATE_LIMIT_REQUESTS_PER_MINUTE,
    window_seconds=60,
)


async def check_rate_limit(request: Request) -> RateLimitResult:
    """Dependency do FastAPI que extrai o identificador do cliente e valida o rate limit."""
    # Prioriza IP real via headers de proxy reverso (ex: Cloudflare, Traefik, Nginx)
    forwarded = request.headers.get("X-Forwarded-For")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "127.0.0.1")

    # Identificador único por IP ou token
    identifier = f"ip:{client_ip}"
    result = await rate_limiter.is_allowed(identifier)

    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Rate limit exceeded",
                "message": f"Limite de {result.limit} requisições por minuto atingido.",
                "retry_after_seconds": result.reset_seconds,
            },
            headers={
                "X-RateLimit-Limit": str(result.limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(result.reset_seconds),
                "Retry-After": str(result.reset_seconds),
            },
        )

    return result
