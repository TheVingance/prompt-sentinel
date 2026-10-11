import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import UUID

from src.core.database import Base


class Tenant(Base):
    """Representa uma organização, departamento ou cliente em ambiente Multi-Tenant."""

    __tablename__ = "tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    slug = Column(String(50), unique=True, nullable=False, index=True)
    api_key_hash = Column(String(64), unique=True, nullable=False, index=True)
    api_key_prefix = Column(String(16), nullable=False)
    rate_limit_rpm = Column(Integer, nullable=False, default=60)
    monthly_budget_usd = Column(Float, nullable=False, default=500.0)
    current_spend_usd = Column(Float, nullable=False, default=0.0)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
