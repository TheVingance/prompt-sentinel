import uuid
from datetime import UTC, datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID

from src.core.database import Base


class AttackSignature(Base):
    """Assinaturas de ataques conhecidos indexadas com pgvector para busca de similaridade."""

    __tablename__ = "attack_signatures"

    id = Column(Integer, primary_key=True, autoincrement=True)
    pattern_name = Column(String(100), nullable=False, index=True)
    category = Column(String(50), nullable=False, default="prompt_injection")
    severity = Column(String(20), nullable=False, default="critical")
    example_text = Column(Text, nullable=False)
    # Vetores de 384 dimensões (típico de BGE-small / all-MiniLM-L6)
    embedding = Column(Vector(384), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class AuditIncident(Base):
    """Trilha de auditoria criptografada e compliance para tentativas de ataque bloqueadas."""

    __tablename__ = "audit_incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_ip = Column(String(45), nullable=False, index=True)
    threat_category = Column(String(50), nullable=False)
    threat_severity = Column(String(20), nullable=False)
    reason = Column(Text, nullable=False)
    matched_pattern = Column(String(100), nullable=True)
    similarity_score = Column(Float, nullable=True)
    sanitized_prompt_sample = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
