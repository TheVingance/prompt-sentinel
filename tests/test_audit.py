import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from benchmarks.run_benchmark import run_benchmark
from src.core.config import settings
from src.core.database import get_db_session
from src.main import app
from src.models.security import AuditIncident
from src.schemas.security import (
    SecurityIncidentResponse,
    ThreatCategory,
    ThreatSeverity,
)


@pytest.mark.asyncio
async def test_audit_endpoints_unauthorized():
    """Valida rejeição com 401 caso não seja fornecida API Key válida."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res1 = await ac.get("/v1/audit/incidents")
        res2 = await ac.get("/v1/audit/metrics")
    assert res1.status_code == 401 or res1.status_code == 422
    assert res2.status_code == 401 or res2.status_code == 422


@pytest.mark.asyncio
async def test_audit_incidents_listing():
    """Valida retorno paginado de incidentes com filtros."""
    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}

    sample_incident = AuditIncident(
        id=uuid.uuid4(),
        client_ip="192.168.1.50",
        threat_category="jailbreak",
        threat_severity="critical",
        reason="Teste de incidente",
        matched_pattern="DAN Jailbreak",
        similarity_score=0.93,
        sanitized_prompt_sample="Exemplo de prompt",
        created_at=datetime.now(UTC),
    )

    mock_db = AsyncMock()
    # Mock do total (count)
    mock_count_res = MagicMock()
    mock_count_res.scalar.return_value = 1
    # Mock da lista de incidentes
    mock_items_res = MagicMock()
    mock_items_res.scalars.return_value.all.return_value = [sample_incident]

    mock_db.execute.side_effect = [mock_count_res, mock_items_res]

    app.dependency_overrides[get_db_session] = lambda: mock_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.get("/v1/audit/incidents?limit=10&offset=0", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["threat_category"] == "jailbreak"
        assert data["items"][0]["similarity_score"] == 0.93
    finally:
        app.dependency_overrides.pop(get_db_session, None)


@pytest.mark.asyncio
async def test_audit_metrics_aggregation():
    """Valida sumário estatístico consolidado das métricas de mitigação."""
    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}

    mock_db = AsyncMock()
    # Mock dos 5 selects executados em get_audit_metrics
    mock_total = MagicMock()
    mock_total.scalar.return_value = 42

    mock_24h = MagicMock()
    mock_24h.scalar.return_value = 10

    mock_by_cat = MagicMock()
    mock_by_cat.all.return_value = [("jailbreak", 30), ("prompt_injection", 12)]

    mock_by_sev = MagicMock()
    mock_by_sev.all.return_value = [("critical", 25), ("high", 17)]

    mock_avg = MagicMock()
    mock_avg.scalar.return_value = 0.885

    mock_cache_stats = MagicMock()
    # (cache_hits, saved_usd, tokens_saved, total_entries)
    mock_cache_stats.first.return_value = (8, 0.0245, 450, 12)

    mock_db.execute.side_effect = [
        mock_total,
        mock_24h,
        mock_by_cat,
        mock_by_sev,
        mock_avg,
        mock_cache_stats,
    ]

    app.dependency_overrides[get_db_session] = lambda: mock_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.get("/v1/audit/metrics", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total_incidents_recorded"] == 42
        assert data["incidents_last_24h"] == 10
        assert data["by_category"]["jailbreak"] == 30
        assert data["average_similarity_score"] == 0.885
        assert data["total_cache_hits"] == 8
        assert data["total_saved_usd"] == 0.0245
        assert data["total_tokens_saved"] == 450
    finally:
        app.dependency_overrides.pop(get_db_session, None)


@pytest.mark.asyncio
async def test_benchmark_runner():
    """Valida execução da suite de benchmark sem falhas."""

    async def mock_analyze(text, session, client_ip="127.0.0.1"):
        text_lower = text.lower()
        if "dan" in text_lower or "disregard" in text_lower or "ignore" in text_lower:
            incident = SecurityIncidentResponse(
                incident_id="bench-test-uuid",
                category=ThreatCategory.JAILBREAK,
                severity=ThreatSeverity.CRITICAL,
                reason="Bloqueio simulado de benchmark",
            )
            return True, incident
        return False, None

    with patch(
        "src.pipeline.semantic_detector.semantic_detector.analyze",
        side_effect=mock_analyze,
    ):
        summary = await run_benchmark(total_requests=12, concurrency=4)

    assert summary["total_requests"] == 12
    assert summary["throughput_req_per_sec"] > 0
    assert summary["latency_p50_ms"] >= 0
    assert summary["attack_block_rate_pct"] == 100.0
