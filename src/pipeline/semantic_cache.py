import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.redis import get_redis
from src.models.cache import SemanticCacheEntry
from src.services.embeddings import embedding_service

logger = logging.getLogger(__name__)

# Preços oficiais por 1.000.000 tokens (Input / Output USD)
PRICING_PER_1M_TOKENS: dict[str, dict[str, float]] = {
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4": {"input": 30.00, "output": 60.00},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    "default": {"input": 1.50, "output": 5.00},
}


def calculate_saved_cost(model_name: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Calcula a economia financeira exata em USD com base na contagem de tokens."""
    rates = PRICING_PER_1M_TOKENS.get(model_name, PRICING_PER_1M_TOKENS["default"])
    input_cost = (prompt_tokens * rates["input"]) / 1_000_000.0
    output_cost = (completion_tokens * rates["output"]) / 1_000_000.0
    return round(input_cost + output_cost, 6)


@dataclass
class SemanticCacheHit:
    """Representa um resultado positivo (Hit) retornado pelo cache semântico."""

    response_text: str
    model_name: str
    similarity_score: float
    saved_cost_usd: float
    prompt_tokens: int
    completion_tokens: int
    hit_count: int


class SemanticCache:
    """Gerenciador de Cache Semântico vetorial com cálculo FinOps e indexação pgvector."""

    def __init__(
        self,
        threshold: float | None = None,
        enabled: bool | None = None,
        ttl_seconds: int | None = None,
    ):
        self.threshold = threshold if threshold is not None else settings.CACHE_SIMILARITY_THRESHOLD
        self.enabled = enabled if enabled is not None else settings.SEMANTIC_CACHE_ENABLED
        self.ttl_seconds = ttl_seconds if ttl_seconds is not None else settings.CACHE_TTL_SECONDS

    async def get(
        self,
        session: AsyncSession,
        prompt: str,
        model: str = "gpt-4o",
        threshold: float | None = None,
    ) -> SemanticCacheHit | None:
        """Verifica se existe resposta semanticamente equivalente no pgvector."""
        if not self.enabled or not prompt or not prompt.strip():
            return None

        effective_threshold = threshold if threshold is not None else self.threshold
        query_vector = embedding_service.get_embedding(prompt)
        now_utc = datetime.now(UTC)

        try:
            cosine_dist = SemanticCacheEntry.embedding.cosine_distance(query_vector)
            similarity_expr = (1 - cosine_dist).label("similarity")

            stmt = (
                select(SemanticCacheEntry, similarity_expr)
                .where(SemanticCacheEntry.ttl_expires_at > now_utc)
                .order_by(cosine_dist)
                .limit(1)
            )

            result = await session.execute(stmt)
            match = result.first()

            if match is not None:
                entry, similarity = match
                similarity_float = float(similarity)

                if similarity_float >= effective_threshold:
                    saved_usd = calculate_saved_cost(
                        model_name=entry.model_name,
                        prompt_tokens=entry.prompt_tokens,
                        completion_tokens=entry.completion_tokens,
                    )

                    # Atualiza contador no banco
                    entry.hit_count += 1
                    entry.cost_saved_usd += saved_usd
                    await session.commit()

                    # Atualiza métricas atômicas no Redis se disponível
                    redis = get_redis()
                    if redis is not None:
                        try:
                            await redis.incrbyfloat("sentinel:finops:saved_usd", saved_usd)
                            await redis.incr("sentinel:finops:cache_hits")
                            await redis.incrby(
                                "sentinel:finops:tokens_saved",
                                entry.prompt_tokens + entry.completion_tokens,
                            )
                        except Exception as r_err:
                            logger.warning(f"Erro ao atualizar métricas no Redis: {r_err}")

                    return SemanticCacheHit(
                        response_text=entry.response_text,
                        model_name=entry.model_name,
                        similarity_score=similarity_float,
                        saved_cost_usd=saved_usd,
                        prompt_tokens=entry.prompt_tokens,
                        completion_tokens=entry.completion_tokens,
                        hit_count=entry.hit_count,
                    )

        except Exception as exc:
            logger.warning(f"Erro ao consultar cache semântico: {exc}")

        return None

    async def set(
        self,
        session: AsyncSession,
        prompt: str,
        response: str,
        model: str = "gpt-4o",
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        ttl_seconds: int | None = None,
    ) -> None:
        """Salva uma nova consulta e resposta no cache vetorial com seu embedding."""
        if not self.enabled or not prompt or not response:
            return

        ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds
        expires_at = datetime.now(UTC) + timedelta(seconds=ttl)
        vector = embedding_service.get_embedding(prompt)

        try:
            new_entry = SemanticCacheEntry(
                prompt_text=prompt.strip(),
                embedding=vector,
                response_text=response.strip(),
                model_name=model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cost_saved_usd=0.0,
                hit_count=1,
                ttl_expires_at=expires_at,
            )
            session.add(new_entry)
            await session.commit()

            redis = get_redis()
            if redis is not None:
                try:
                    await redis.incr("sentinel:finops:cache_entries")
                except Exception as r_err:
                    logger.warning(f"Erro ao registrar entrada no Redis: {r_err}")

        except Exception as exc:
            logger.warning(f"Erro ao persistir entrada no cache semântico: {exc}")


semantic_cache = SemanticCache()
