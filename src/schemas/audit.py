from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class AuditIncidentItem(BaseModel):
    id: UUID
    client_ip: str
    threat_category: str
    threat_severity: str
    reason: str
    matched_pattern: str | None = None
    similarity_score: float | None = None
    sanitized_prompt_sample: str
    created_at: datetime


class AuditIncidentsResponse(BaseModel):
    total: int = Field(..., description="Quantidade total de incidentes correspondentes")
    limit: int = Field(..., description="Tamanho da página")
    offset: int = Field(..., description="Deslocamento da paginação")
    items: list[AuditIncidentItem]


class AuditMetricsResponse(BaseModel):
    total_incidents_recorded: int = Field(..., description="Total histórico de ameaças bloqueadas")
    incidents_last_24h: int = Field(..., description="Ameaças bloqueadas nas últimas 24 horas")
    by_category: dict[str, int] = Field(default_factory=dict, description="Distribuição por categoria OWASP")
    by_severity: dict[str, int] = Field(default_factory=dict, description="Distribuição por gravidade")
    average_similarity_score: float = Field(default=0.0, description="Média de similaridade dos ataques semânticos")

    # Métricas FinOps & Cache Semântico
    total_cache_hits: int = Field(default=0, description="Total de requisições servidas via cache semântico")
    cache_hit_ratio: float = Field(default=0.0, description="Taxa percentual de acerto no cache")
    total_saved_usd: float = Field(default=0.0, description="Economia financeira total estimada em USD")
    total_tokens_saved: int = Field(default=0, description="Total de tokens LLM poupados")
