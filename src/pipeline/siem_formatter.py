"""Formatador de eventos de segurança corporativa para SIEM (CEF / LEEF / JSON)."""

from typing import Any

from src.models.security import AuditIncident
from src.models.tenant import Tenant


class SIEMFormatter:
    """Traduz incidentes de segurança para os formatos padronizados de SIEM (ArcSight CEF e QRadar LEEF)."""

    SEVERITY_MAP: dict[str, int] = {
        "critical": 10,
        "high": 8,
        "medium": 6,
        "low": 3,
        "info": 1,
    }

    @classmethod
    def get_numeric_severity(cls, severity_str: str) -> int:
        """Converte a severidade textual em número de 1 a 10 para conformidade com CEF."""
        return cls.SEVERITY_MAP.get(severity_str.lower(), 5)

    @classmethod
    def escape_cef_header(cls, val: str) -> str:
        """Escapa barras verticais e contra-barras em cabeçalhos CEF."""
        return val.replace("\\", "\\\\").replace("|", "\\|")

    @classmethod
    def escape_cef_value(cls, val: str) -> str:
        """Escapa caracteres especiais em valores da extensão CEF."""
        return val.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", "")

    @classmethod
    def format_cef(
        cls,
        incident: AuditIncident,
        tenant: Tenant | None = None,
        model_name: str = "llm-proxy",
    ) -> str:
        """Formata um AuditIncident no padrão ArcSight Common Event Format (CEF:0)."""
        vendor = "PromptSentinel"
        product = "AI-Firewall"
        version = "1.0.0"
        event_class = cls.escape_cef_header(incident.threat_category.upper())
        name = cls.escape_cef_header(incident.reason)
        severity = cls.get_numeric_severity(incident.threat_severity)

        # Montagem dos pares chave=valor de extensão
        extensions: list[str] = [
            f"src={cls.escape_cef_value(incident.client_ip)}",
            "act=blocked",
            f"deviceVendor={vendor}",
            f"deviceProduct={product}",
        ]

        tenant_identifier = tenant.slug if tenant else "default"
        extensions.append(f"suser={cls.escape_cef_value(tenant_identifier)}")

        if tenant and tenant.name:
            extensions.append(f"cs3={cls.escape_cef_value(tenant.name)}")
            extensions.append("cs3Label=TenantName")

        if model_name:
            extensions.append(f"cs1={cls.escape_cef_value(model_name)}")
            extensions.append("cs1Label=ModelName")

        if incident.matched_pattern:
            extensions.append(f"cs2={cls.escape_cef_value(incident.matched_pattern)}")
            extensions.append("cs2Label=MatchedPattern")

        if incident.similarity_score is not None:
            extensions.append(f"cn1={int(incident.similarity_score * 100)}")
            extensions.append("cn1Label=SimilarityPercent")

        if incident.created_at:
            epoch_ms = int(incident.created_at.timestamp() * 1000)
            extensions.append(f"rt={epoch_ms}")

        extension_str = " ".join(extensions)
        return f"CEF:0|{vendor}|{product}|{version}|{event_class}|{name}|{severity}|{extension_str}"

    @classmethod
    def format_leef(
        cls,
        incident: AuditIncident,
        tenant: Tenant | None = None,
        model_name: str = "llm-proxy",
    ) -> str:
        """Formata um AuditIncident no padrão IBM QRadar LEEF (Log Event Extended Format 2.0)."""
        vendor = "PromptSentinel"
        product = "AI-Firewall"
        version = "1.0.0"
        event_id = incident.threat_category.upper()
        severity = cls.get_numeric_severity(incident.threat_severity)
        tenant_identifier = tenant.slug if tenant else "default"

        fields = [
            f"src={incident.client_ip}",
            f"usr={tenant_identifier}",
            f"sev={severity}",
            "act=blocked",
            f"model={model_name}",
            f"reason={incident.reason.replace('\t', ' ')}",
        ]
        if incident.matched_pattern:
            fields.append(f"pattern={incident.matched_pattern}")

        payload = "\t".join(fields)
        return f"LEEF:2.0|{vendor}|{product}|{version}|{event_id}|\t{payload}"

    @classmethod
    def format_json(
        cls,
        incident: AuditIncident,
        tenant: Tenant | None = None,
        model_name: str = "llm-proxy",
    ) -> dict[str, Any]:
        """Retorna representação JSON estruturada para ingestão em Elastic SIEM / Splunk HEC."""
        return {
            "incident_id": str(incident.id),
            "timestamp": incident.created_at.isoformat() if incident.created_at else None,
            "vendor": "PromptSentinel",
            "product": "AI-Firewall",
            "version": "1.0.0",
            "client_ip": incident.client_ip,
            "tenant": {
                "id": str(tenant.id) if tenant else None,
                "slug": tenant.slug if tenant else "default",
                "name": tenant.name if tenant else "Default Organization",
            },
            "threat": {
                "category": incident.threat_category,
                "severity": incident.threat_severity,
                "severity_score": cls.get_numeric_severity(incident.threat_severity),
                "reason": incident.reason,
                "matched_pattern": incident.matched_pattern,
                "similarity_score": incident.similarity_score,
            },
            "model_requested": model_name,
            "action": "blocked",
        }
