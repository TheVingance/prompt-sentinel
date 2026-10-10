from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routes.proxy import verify_api_key
from src.core.database import get_db_session
from src.models.security import AuditIncident
from src.schemas.audit import (
    AuditIncidentItem,
    AuditIncidentsResponse,
    AuditMetricsResponse,
)

router = APIRouter(prefix="/v1/audit", tags=["Security Audit & Analytics"])


@router.get(
    "/incidents",
    response_model=AuditIncidentsResponse,
    summary="Listar incidentes de segurança interceptados",
)
async def list_incidents(
    category: str | None = Query(None, description="Filtrar por categoria (ex: jailbreak, prompt_injection)"),
    severity: str | None = Query(None, description="Filtrar por gravidade (ex: critical, high)"),
    limit: int = Query(50, ge=1, le=100, description="Limite por página"),
    offset: int = Query(0, ge=0, description="Offset de paginação"),
    _token: str = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db_session),
) -> AuditIncidentsResponse:
    """Retorna os registros de incidentes bloqueados pelo firewall de IA com suporte a paginação e filtros."""
    query = select(AuditIncident)
    count_query = select(func.count(AuditIncident.id))

    if category:
        query = query.where(AuditIncident.threat_category == category)
        count_query = count_query.where(AuditIncident.threat_category == category)
    if severity:
        query = query.where(AuditIncident.threat_severity == severity)
        count_query = count_query.where(AuditIncident.threat_severity == severity)

    # Executa contagem total
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Busca itens paginados ordenados pelo mais recente
    query = query.order_by(AuditIncident.created_at.desc()).offset(offset).limit(limit)
    items_result = await db.execute(query)
    incidents = items_result.scalars().all()

    items = [
        AuditIncidentItem(
            id=inc.id,
            client_ip=inc.client_ip,
            threat_category=inc.threat_category,
            threat_severity=inc.threat_severity,
            reason=inc.reason,
            matched_pattern=inc.matched_pattern,
            similarity_score=inc.similarity_score,
            sanitized_prompt_sample=inc.sanitized_prompt_sample,
            created_at=inc.created_at,
        )
        for inc in incidents
    ]

    return AuditIncidentsResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=items,
    )


@router.get(
    "/metrics",
    response_model=AuditMetricsResponse,
    summary="Métricas consolidadas de mitigação de ataques",
)
async def get_audit_metrics(
    _token: str = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db_session),
) -> AuditMetricsResponse:
    """Gera o sumário estatístico consolidado dos ataques interceptados pelo PromptSentinel."""
    # 1. Total histórico
    total_res = await db.execute(select(func.count(AuditIncident.id)))
    total_incidents = total_res.scalar() or 0

    # 2. Incidentes nas últimas 24h
    since_24h = datetime.now(UTC) - timedelta(hours=24)
    last_24h_res = await db.execute(
        select(func.count(AuditIncident.id)).where(AuditIncident.created_at >= since_24h)
    )
    incidents_24h = last_24h_res.scalar() or 0

    # 3. Distribuição por categoria
    cat_stmt = select(AuditIncident.threat_category, func.count(AuditIncident.id)).group_by(
        AuditIncident.threat_category
    )
    cat_res = await db.execute(cat_stmt)
    by_category = {row[0]: row[1] for row in cat_res.all()}

    # 4. Distribuição por severidade
    sev_stmt = select(AuditIncident.threat_severity, func.count(AuditIncident.id)).group_by(
        AuditIncident.threat_severity
    )
    sev_res = await db.execute(sev_stmt)
    by_severity = {row[0]: row[1] for row in sev_res.all()}

    # 5. Média do score de similaridade
    avg_score_res = await db.execute(select(func.avg(AuditIncident.similarity_score)))
    avg_similarity = avg_score_res.scalar() or 0.0

    return AuditMetricsResponse(
        total_incidents_recorded=total_incidents,
        incidents_last_24h=incidents_24h,
        by_category=by_category,
        by_severity=by_severity,
        average_similarity_score=round(float(avg_similarity), 4),
    )
