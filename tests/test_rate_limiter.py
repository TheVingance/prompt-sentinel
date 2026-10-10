from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from src.core.config import settings
from src.main import app
from src.pipeline.rate_limiter import RateLimitResult, SlidingWindowRateLimiter


@pytest.mark.asyncio
async def test_sliding_window_unit_fallback_without_redis():
    """Valida que o limitador opera em fail-open gracioso se Redis for None."""
    limiter = SlidingWindowRateLimiter(limit=10, window_seconds=60)
    result = await limiter.is_allowed("test-client", redis_client=None)
    assert result.allowed is True
    assert result.limit == 10
    assert result.remaining == 9


@pytest.mark.asyncio
async def test_proxy_includes_rate_limit_headers():
    """Valida se o endpoint /v1/chat/completions inclui os cabeçalhos de rate limit."""
    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Olá, teste de cabeçalhos de rate limit"}],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/v1/chat/completions", json=payload, headers=headers)

    assert response.status_code == 200
    assert "X-RateLimit-Limit" in response.headers
    assert "X-RateLimit-Remaining" in response.headers
    assert "X-RateLimit-Reset" in response.headers


@pytest.mark.asyncio
async def test_proxy_returns_429_when_rate_limit_exceeded():
    """Valida se uma requisição acima do limite retorna HTTP 429 Too Many Requests."""
    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Teste de estouro de cota"}],
    }

    # Mocka a decisão do rate limiter simulando limite estourado
    mocked_result = RateLimitResult(
        allowed=False,
        limit=5,
        remaining=0,
        reset_seconds=45,
    )

    with patch("src.pipeline.rate_limiter.rate_limiter.is_allowed", new=AsyncMock(return_value=mocked_result)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post("/v1/chat/completions", json=payload, headers=headers)

    assert response.status_code == 429
    assert response.headers.get("Retry-After") == "45"
    assert response.headers.get("X-RateLimit-Remaining") == "0"
    data = response.json()
    assert "detail" in data
    assert data["detail"]["error"] == "Rate limit exceeded"
    assert data["detail"]["retry_after_seconds"] == 45
