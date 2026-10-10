import pytest
from httpx import ASGITransport, AsyncClient

from src.main import app


@pytest.mark.asyncio
async def test_root_endpoint():
    """Testa se o endpoint raiz responde corretamente com metadados do serviço."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "PromptSentinel" in data["service"]


@pytest.mark.asyncio
async def test_health_check_structure():
    """Testa se o endpoint /health retorna o cabeçalho X-Process-Time-Ms e formato adequado."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/health")
    assert response.status_code == 200
    assert "X-Process-Time-Ms" in response.headers
    data = response.json()
    assert "services" in data
    assert "latency_ms" in data
