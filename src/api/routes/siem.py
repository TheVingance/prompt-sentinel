"""Rotas de integração e exportação de telemetria de segurança para SIEM corporativo."""

from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db_session as get_db
from src.core.metrics import sentinel_siem_events_exported_total
from src.core.tenant import get_current_tenant
from src.models.security import AuditIncident
from src.models.tenant import Tenant
from src.pipeline.siem_formatter import SIEMFormatter
from src.schemas.tenant import SIEMEventFormat

router = APIRouter(prefix="/v1/siem", tags=["SIEM & SecOps Forwarder"])


@router.get(
    "/events",
    summary="Exportar eventos e incidentes de segurança para SIEM (CEF / LEEF / JSON)",
    responses={
        200: {
            "description": "Eventos no formato ArcSight CEF, QRadar LEEF ou JSON estruturado.",
            "content": {
                "text/plain": {"schema": {"type": "string"}},
                "application/json": {"schema": {"type": "array"}},
            },
        }
    },
)
async def export_siem_events(
    format: SIEMEventFormat = Query(
        default=SIEMEventFormat.CEF,
        description="Formato de exportação: 'cef' (ArcSight), 'leef' (QRadar) ou 'json' (Elastic/Splunk).",
    ),
    limit: int = Query(
        default=50, ge=1, le=500, description="Quantidade máxima de eventos a recuperar"
    ),
    severity: str | None = Query(
        default=None, description="Filtro opcional por severidade (critical, high, medium, low)"
    ),
    category: str | None = Query(
        default=None, description="Filtro opcional por categoria de ameaça"
    ),
    current_tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Exporta trilha de incidentes de segurança formatada para integração com SIEMs/SOCs."""
    query = select(AuditIncident).order_by(AuditIncident.created_at.desc()).limit(limit)

    # Se não for o tenant master, isola os eventos estritamente ao tenant chamador
    if current_tenant.slug != "default":
        query = query.where(AuditIncident.tenant_id == current_tenant.id)

    if severity:
        query = query.where(AuditIncident.threat_severity == severity.lower())
    if category:
        query = query.where(AuditIncident.threat_category == category.lower())

    result = await db.execute(query)
    incidents = list(result.scalars().all())

    if incidents:
        sentinel_siem_events_exported_total.labels(format=format.value).inc(len(incidents))

    # Mapa de tenants para enriquecer logs
    tenant_ids = {inc.tenant_id for inc in incidents if inc.tenant_id}
    tenant_map: dict[Any, Tenant] = {}
    if tenant_ids:
        t_stmt = select(Tenant).where(Tenant.id.in_(tenant_ids))
        t_res = await db.execute(t_stmt)
        tenant_map = {t.id: t for t in t_res.scalars().all()}

    if format == SIEMEventFormat.CEF:
        lines = [
            SIEMFormatter.format_cef(
                incident=inc,
                tenant=tenant_map.get(
                    inc.tenant_id, current_tenant if inc.tenant_id == current_tenant.id else None
                ),
            )
            for inc in incidents
        ]
        return Response(content="\n".join(lines), media_type="text/plain; charset=utf-8")

    if format == SIEMEventFormat.LEEF:
        lines = [
            SIEMFormatter.format_leef(
                incident=inc,
                tenant=tenant_map.get(
                    inc.tenant_id, current_tenant if inc.tenant_id == current_tenant.id else None
                ),
            )
            for inc in incidents
        ]
        return Response(content="\n".join(lines), media_type="text/plain; charset=utf-8")

    # JSON estruturado
    events_json = [
        SIEMFormatter.format_json(
            incident=inc,
            tenant=tenant_map.get(
                inc.tenant_id, current_tenant if inc.tenant_id == current_tenant.id else None
            ),
        )
        for inc in incidents
    ]
    return JSONResponse(content=events_json)
