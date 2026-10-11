"""Gerenciador e resolvedor de Tenants para ambiente corporativo Multi-Tenant."""

import hashlib
import secrets
import uuid
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.database import get_db_session as get_db
from src.models.tenant import Tenant


def hash_api_key(raw_key: str) -> str:
    """Calcula o hash SHA-256 de uma chave de API."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_tenant_api_key(slug: str) -> tuple[str, str, str]:
    """Gera uma nova chave segura de tenant. Retorna (raw_key, api_key_hash, api_key_prefix)."""
    random_token = secrets.token_hex(16)
    raw_key = f"sentinel-org-{slug}-{random_token}"
    api_key_hash = hash_api_key(raw_key)
    api_key_prefix = f"sentinel-org-{slug[:4]}..."
    return raw_key, api_key_hash, api_key_prefix


# Cache em memória para resolução ultrarrápida de Tenants (< 0.1ms)
_tenant_cache: dict[str, Tenant] = {}


def cache_tenant(tenant: Tenant) -> None:
    """Registra tenant no cache local."""
    _tenant_cache[tenant.api_key_hash] = tenant


def invalidate_tenant_cache(api_key_hash: str) -> None:
    """Invalida tenant do cache local."""
    _tenant_cache.pop(api_key_hash, None)


def clear_tenant_cache() -> None:
    """Limpa todo o cache de tenants (usado em testes)."""
    _tenant_cache.clear()


# Objeto estático para requisições usando a chave mestre do sistema
DEFAULT_MASTER_TENANT = Tenant(
    id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
    name="Master Organization",
    slug="default",
    api_key_hash="master",
    api_key_prefix="sentinel-master",
    rate_limit_rpm=1000,
    monthly_budget_usd=999999.0,
    current_spend_usd=0.0,
    is_active=True,
)


async def resolve_tenant_from_key(
    raw_key: str,
    db: AsyncSession,
) -> Tenant | None:
    """Resolve a organização associada a uma API Key no banco ou cache."""
    # Se for a chave mestra global configurada no ambiente
    if raw_key == settings.SENTINEL_API_KEY:
        return DEFAULT_MASTER_TENANT

    # Validação rápida de formato de chave de organização
    if not raw_key.startswith("sentinel-org-"):
        return None

    key_hash = hash_api_key(raw_key)
    if key_hash in _tenant_cache:
        cached = _tenant_cache[key_hash]
        if cached.is_active:
            return cached

    # Consulta no banco de dados com tratamento defensivo
    try:
        stmt = select(Tenant).where(Tenant.api_key_hash == key_hash, Tenant.is_active.is_(True))
        result = await db.execute(stmt)
        tenant = result.scalar_one_or_none()
        if tenant:
            cache_tenant(tenant)
        return tenant
    except Exception:
        return None


async def get_current_tenant(
    authorization: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    """Dependência FastAPI que autentica e extrai a organização chamadora."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header Authorization Bearer ausente ou inválido.",
        )

    raw_token = authorization.split("Bearer ", 1)[1].strip()
    tenant = await resolve_tenant_from_key(raw_token, db)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key de organização inválida, revogada ou inativa.",
        )

    # Verificação FinOps de estouro de orçamento
    if tenant.current_spend_usd >= tenant.monthly_budget_usd:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "monthly_budget_exceeded",
                "message": (
                    f"Orçamento mensal da organização '{tenant.name}' esgotado "
                    f"(${tenant.current_spend_usd:.2f} / ${tenant.monthly_budget_usd:.2f} USD)."
                ),
                "tenant": tenant.slug,
            },
        )

    return tenant
