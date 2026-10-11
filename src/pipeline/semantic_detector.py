import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.models.security import AttackSignature, AuditIncident
from src.schemas.security import (
    SecurityIncidentResponse,
    ThreatCategory,
    ThreatSeverity,
)
from src.services.embeddings import embedding_service


class SemanticDetector:
    """Detector de ameaças de Prompt Injection e Jailbreak baseado em similaridade semântica

    utilizando pgvector e representações vetoriais locais.
    """

    def __init__(self, threshold: float | None = None):
        self.threshold = threshold or settings.SIMILARITY_THRESHOLD

    async def analyze(
        self,
        text: str,
        session: AsyncSession,
        client_ip: str = "127.0.0.1",
        tenant_id: uuid.UUID | None = None,
    ) -> tuple[bool, SecurityIncidentResponse | None]:
        """Compara o embedding do texto com a base de assinaturas de ataque no pgvector."""
        if not text or not text.strip():
            return False, None

        query_vector = embedding_service.get_embedding(text)

        try:
            # Similaridade por cosseno no pgvector (1 - distância de cosseno)
            cosine_dist = AttackSignature.embedding.cosine_distance(query_vector)
            similarity_expr = (1 - cosine_dist).label("similarity")

            stmt = (
                select(
                    AttackSignature.pattern_name,
                    AttackSignature.category,
                    AttackSignature.severity,
                    similarity_expr,
                )
                .order_by(cosine_dist)
                .limit(1)
            )

            result = await session.execute(stmt)
            match = result.first()

            if match is not None:
                pattern_name, category_str, severity_str, similarity = match

                if similarity >= self.threshold:
                    incident_id = str(uuid.uuid4())
                    reason_msg = (
                        f"Detecção semântica de alta similaridade ({similarity:.2%}) "
                        f"com a assinatura de ataque: '{pattern_name}'"
                    )

                    # Persiste o incidente na trilha de auditoria para conformidade
                    audit_record = AuditIncident(
                        id=uuid.UUID(incident_id),
                        tenant_id=tenant_id,
                        client_ip=client_ip,
                        threat_category=category_str,
                        threat_severity=severity_str,
                        reason=reason_msg,
                        matched_pattern=pattern_name,
                        similarity_score=float(similarity),
                        sanitized_prompt_sample=text[:500],  # Primeiros 500 caracteres
                    )
                    session.add(audit_record)
                    await session.commit()

                    # Mapeia para enums do schema de resposta
                    threat_cat = (
                        ThreatCategory.JAILBREAK
                        if category_str == "jailbreak"
                        else ThreatCategory.PROMPT_INJECTION
                    )
                    threat_sev = (
                        ThreatSeverity.CRITICAL
                        if severity_str == "critical"
                        else ThreatSeverity.HIGH
                    )

                    incident_response = SecurityIncidentResponse(
                        incident_id=incident_id,
                        category=threat_cat,
                        severity=threat_sev,
                        reason=reason_msg,
                    )
                    return True, incident_response

        except Exception as exc:
            # Em caso de banco vetorial indisponível momentaneamente, loga o aviso e não derruba
            print(f"[SemanticDetector Warning] Erro na consulta ao pgvector: {exc}")

        return False, None


semantic_detector = SemanticDetector()
