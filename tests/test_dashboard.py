import pytest
from httpx import ASGITransport, AsyncClient

from src.main import app


@pytest.mark.asyncio
async def test_dashboard_html_rendering():
    """Valida se a rota /dashboard serve a interface web com HTML válido."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "PromptSentinel" in response.text
    assert "AI FIREWALL" in response.text
    assert "Playground" in response.text


@pytest.mark.asyncio
async def test_static_assets_served():
    """Valida se os arquivos estáticos de CSS e JS são entregues corretamente."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        css_res = await ac.get("/static/dashboard.css")
        js_res = await ac.get("/static/dashboard.js")
    assert css_res.status_code == 200
    assert js_res.status_code == 200


@pytest.mark.asyncio
async def test_root_includes_dashboard_link():
    """Valida se o endpoint raiz inclui o link de navegação para o dashboard."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data.get("dashboard") == "/dashboard"
