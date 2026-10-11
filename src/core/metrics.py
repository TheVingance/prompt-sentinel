"""Módulo central de observabilidade e métricas Prometheus corporativas."""

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# 1. Contador geral de requisições do gateway
sentinel_requests_total = Counter(
    "sentinel_requests_total",
    "Total de requisições recebidas pelo gateway PromptSentinel",
    ["model", "status"],
)

# 2. Contador de ameaças de segurança bloqueadas por categoria OWASP e severidade
sentinel_threats_blocked_total = Counter(
    "sentinel_threats_blocked_total",
    "Total de ameaças de segurança bloqueadas pelo firewall PromptSentinel",
    ["category", "severity"],
)

# 3. Métricas FinOps do Cache Semântico
sentinel_cache_hits_total = Counter(
    "sentinel_cache_hits_total",
    "Total de requisições atendidas diretamente pelo cache semântico pgvector",
    ["model"],
)

sentinel_cache_savings_usd_total = Counter(
    "sentinel_cache_savings_usd_total",
    "Economia financeira acumulada pelo cache semântico em dólares (USD)",
    ["model"],
)

sentinel_tokens_saved_total = Counter(
    "sentinel_tokens_saved_total",
    "Volume total de tokens LLM poupados através do cache semântico",
    ["model"],
)

# 4. Contador de mascaramento de dados sensíveis (DLP)
sentinel_pii_redacted_total = Counter(
    "sentinel_pii_redacted_total",
    "Total de entidades sensíveis (PII) detectadas e mascaradas pelo gateway",
    ["entity_type"],
)

# 5. Histograma de latência de ponta a ponta
sentinel_request_duration_seconds = Histogram(
    "sentinel_request_duration_seconds",
    "Distribuição da latência das requisições no gateway PromptSentinel",
    ["endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# 6. Métricas de Resiliência e Tolerância a Falhas (Circuit Breaker & Fallback)
sentinel_fallbacks_total = Counter(
    "sentinel_fallbacks_total",
    "Total de comutações automáticas para modelos de contingência (Fallback)",
    ["from_model", "to_model"],
)

sentinel_circuit_breaker_state = Gauge(
    "sentinel_circuit_breaker_state",
    "Estado do Circuit Breaker por provedor (0=CLOSED, 1=HALF_OPEN, 2=OPEN)",
    ["provider"],
)

# 7. Métricas de Multi-Tenancy & Governança Organizacional
sentinel_tenant_requests_total = Counter(
    "sentinel_tenant_requests_total",
    "Total de requisições segregadas por organização/tenant",
    ["tenant", "status"],
)

# 8. Contador de exportação para SIEM
sentinel_siem_events_exported_total = Counter(
    "sentinel_siem_events_exported_total",
    "Total de eventos de segurança exportados para ferramentas de SIEM",
    ["format"],
)


def get_prometheus_metrics() -> bytes:
    """Gera o payload serializado em formato Prometheus padrão."""
    return generate_latest()


__all__ = [
    "CONTENT_TYPE_LATEST",
    "get_prometheus_metrics",
    "sentinel_cache_hits_total",
    "sentinel_cache_savings_usd_total",
    "sentinel_circuit_breaker_state",
    "sentinel_fallbacks_total",
    "sentinel_pii_redacted_total",
    "sentinel_request_duration_seconds",
    "sentinel_requests_total",
    "sentinel_threats_blocked_total",
    "sentinel_tokens_saved_total",
]
