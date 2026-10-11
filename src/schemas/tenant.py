import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SIEMEventFormat(StrEnum):
    """Formatos suportados para exportação a ferramentas de SIEM/SOC."""

    CEF = "cef"
    LEEF = "leef"
    JSON = "json"


class TenantCreate(BaseModel):
    """Payload para criação de um novo departamento ou tenant."""

    name: str = Field(..., min_length=2, max_length=100, description="Nome da organização/área")
    slug: str = Field(
        ...,
        min_length=2,
        max_length=50,
        pattern=r"^[a-z0-9-]+$",
        description="Identificador único (slug)",
    )
    monthly_budget_usd: float = Field(
        default=500.0, ge=0.0, description="Teto orçamentário mensal em USD"
    )
    rate_limit_rpm: int = Field(
        default=60, ge=1, le=10000, description="Limite de requisições por minuto"
    )


class TenantResponse(BaseModel):
    """Dados públicos de um tenant."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    api_key_prefix: str
    rate_limit_rpm: int
    monthly_budget_usd: float
    current_spend_usd: float
    is_active: bool
    created_at: datetime


class TenantCreatedWithSecret(TenantResponse):
    """Retorno único na criação contendo a chave de API crua."""

    raw_api_key: str = Field(
        ...,
        description="Chave de API gerada. Guarde com segurança, pois não será exibida novamente.",
    )
