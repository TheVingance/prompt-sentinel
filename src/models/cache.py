import uuid
from datetime import UTC, datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID

from src.core.database import Base


class SemanticCacheEntry(Base):
    """Armazena consultas e respostas cacheadas com embeddings para busca por similaridade semântica (FinOps)."""

    __tablename__ = "semantic_cache"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    prompt_text = Column(Text, nullable=False)
    # Embedding L2-normalizado de 384 dimensões
    embedding = Column(Vector(384), nullable=False)
    response_text = Column(Text, nullable=False)
    model_name = Column(String(50), nullable=False, default="gpt-4o")

    # Métricas de consumo e FinOps
    prompt_tokens = Column(Integer, default=0, nullable=False)
    completion_tokens = Column(Integer, default=0, nullable=False)
    cost_saved_usd = Column(Float, default=0.0, nullable=False)
    hit_count = Column(Integer, default=1, nullable=False)

    # Controle de TTL e auditoria
    ttl_expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
