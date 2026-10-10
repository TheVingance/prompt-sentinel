import pytest
from httpx import ASGITransport, AsyncClient

from src.core.config import settings
from src.main import app
from src.pipeline.semantic_cache import (
    SemanticCacheHit,
    calculate_saved_cost,
    semantic_cache,
)


def test_calculate_saved_cost():
    """Valida a precisão matemática do cálculo de custos poupados (FinOps)."""
    # Para GPT-4o: 1000 prompt tokens ($2.50/M) + 500 completion tokens ($10.00/M)
    # (1000 * 2.5 / 1_000_000) + (500 * 10.0 / 1_000_000) = 0.0025 + 0.0050 = 0.0075 USD
    saved_gpt4o = calculate_saved_cost("gpt-4o", 1000, 500)
    assert saved_gpt4o == 0.0075

    # Para GPT-4o-mini: 10000 prompt tokens ($0.15/M) + 2000 completion tokens ($0.60/M)
    # (10000 * 0.15 / 1_000_000) + (2000 * 0.60 / 1_000_000) = 0.0015 + 0.0012 = 0.0027 USD
    saved_mini = calculate_saved_cost("gpt-4o-mini", 10000, 2000)
    assert saved_mini == 0.0027


@pytest.mark.asyncio
async def test_proxy_semantic_cache_miss_then_hit(monkeypatch):
    """Valida o ciclo completo de Cache MISS na primeira chamada e Cache HIT na segunda chamada."""
    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}
    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": "Como implementar busca vetorial em Python com pgvector?",
            }
        ],
    }

    # 1. Primeira Chamada: Simula Cache MISS
    async def mock_cache_get_miss(*args, **kwargs):
        return None

    async def mock_cache_set(*args, **kwargs):
        return None

    monkeypatch.setattr(semantic_cache, "get", mock_cache_get_miss)
    monkeypatch.setattr(semantic_cache, "set", mock_cache_set)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response_miss = await ac.post("/v1/chat/completions", json=payload, headers=headers)

    assert response_miss.status_code == 200
    assert response_miss.headers.get("X-Cache-Status") == "MISS"

    # 2. Segunda Chamada: Simula Cache HIT imediato
    mock_hit = SemanticCacheHit(
        response_text="Resposta recuperada do cache semântico com pgvector.",
        model_name="gpt-4o",
        similarity_score=0.985,
        saved_cost_usd=0.0035,
        prompt_tokens=20,
        completion_tokens=40,
        hit_count=2,
    )

    async def mock_cache_get_hit(*args, **kwargs):
        return mock_hit

    monkeypatch.setattr(semantic_cache, "get", mock_cache_get_hit)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response_hit = await ac.post("/v1/chat/completions", json=payload, headers=headers)

    assert response_hit.status_code == 200
    assert response_hit.headers.get("X-Cache-Status") == "HIT"
    assert response_hit.headers.get("X-Cache-Savings-USD") == "$0.003500"
    assert float(response_hit.headers.get("X-Cache-Similarity")) == 0.9850

    data = response_hit.json()
    assert "choices" in data
    assert data["choices"][0]["message"]["content"] == "Resposta recuperada do cache semântico com pgvector."


@pytest.mark.asyncio
async def test_audit_metrics_includes_finops():
    """Valida se o endpoint /v1/audit/metrics retorna os novos indicadores FinOps."""
    from unittest.mock import AsyncMock, MagicMock

    from src.core.database import get_db_session

    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}

    mock_db = AsyncMock()
    mock_total = MagicMock()
    mock_total.scalar.return_value = 10
    mock_24h = MagicMock()
    mock_24h.scalar.return_value = 5
    mock_by_cat = MagicMock()
    mock_by_cat.all.return_value = []
    mock_by_sev = MagicMock()
    mock_by_sev.all.return_value = []
    mock_avg = MagicMock()
    mock_avg.scalar.return_value = 0.85
    mock_cache = MagicMock()
    mock_cache.first.return_value = (15, 0.0450, 600, 20)

    mock_db.execute.side_effect = [mock_total, mock_24h, mock_by_cat, mock_by_sev, mock_avg, mock_cache]

    app.dependency_overrides[get_db_session] = lambda: mock_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.get("/v1/audit/metrics", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert "total_cache_hits" in data
        assert "cache_hit_ratio" in data
        assert "total_saved_usd" in data
        assert "total_tokens_saved" in data
        assert data["total_cache_hits"] == 15
        assert data["total_saved_usd"] == 0.045
        assert data["total_tokens_saved"] == 600
    finally:
        app.dependency_overrides.pop(get_db_session, None)
