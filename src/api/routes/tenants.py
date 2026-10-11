"""Rotas de administração e gerenciamento de Tenants / Organizações."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.database import get_db_session as get_db
from src.core.tenant import generate_tenant_api_key, invalidate_tenant_cache
from src.models.tenant import Tenant
from src.schemas.tenant import TenantCreate, TenantCreatedWithSecret, TenantResponse

router = APIRouter(prefix="/v1/tenants", tags=["Tenants & Multi-Tenancy"])


def verify_master_admin(authorization: str | None = Header(None)) -> None:
    """Garante que apenas a Master Key do PromptSentinel possa gerenciar tenants."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credencial mestre não fornecida.",
        )
    token = authorization.split("Bearer ", 1)[1].strip()
    if token != settings.SENTINEL_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas a chave mestre do sistema pode gerenciar organizações.",
        )


@router.post(
    "",
    response_model=TenantCreatedWithSecret,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastrar nova organização / departamento",
    dependencies=[Depends(verify_master_admin)],
)
async def create_tenant(
    data: TenantCreate,
    db: AsyncSession = Depends(get_db),
) -> TenantCreatedWithSecret:
    """Cria uma nova organização e gera sua chave de API segura."""
    # Verifica unicidade do slug
    existing = await db.execute(select(Tenant).where(Tenant.slug == data.slug))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Já existe uma organização cadastrada com o slug '{data.slug}'.",
        )

    raw_key, api_key_hash, api_key_prefix = generate_tenant_api_key(data.slug)

    new_tenant = Tenant(
        id=uuid.uuid4(),
        name=data.name,
        slug=data.slug,
        api_key_hash=api_key_hash,
        api_key_prefix=api_key_prefix,
        rate_limit_rpm=data.rate_limit_rpm,
        monthly_budget_usd=data.monthly_budget_usd,
        current_spend_usd=0.0,
        is_active=True,
        created_at=datetime.now(UTC),
    )
    db.add(new_tenant)
    await db.commit()
    await db.refresh(new_tenant)

    return TenantCreatedWithSecret(
        id=new_tenant.id,
        name=new_tenant.name,
        slug=new_tenant.slug,
        api_key_prefix=new_tenant.api_key_prefix,
        rate_limit_rpm=new_tenant.rate_limit_rpm,
        monthly_budget_usd=new_tenant.monthly_budget_usd,
        current_spend_usd=new_tenant.current_spend_usd,
        is_active=new_tenant.is_active,
        created_at=new_tenant.created_at,
        raw_api_key=raw_key,
    )


@router.get(
    "",
    response_model=list[TenantResponse],
    summary="Listar organizações cadastradas",
    dependencies=[Depends(verify_master_admin)],
)
async def list_tenants(
    db: AsyncSession = Depends(get_db),
) -> list[Tenant]:
    """Lista todas as organizações cadastradas com seus respectivos orçamentos e consumo."""
    stmt = select(Tenant).order_by(Tenant.created_at.desc())
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get(
    "/{tenant_id}",
    response_model=TenantResponse,
    summary="Obter detalhes de uma organização",
    dependencies=[Depends(verify_master_admin)],
)
async def get_tenant_details(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    """Busca detalhes de uma organização específica por UUID."""
    stmt = select(Tenant).where(Tenant.id == tenant_id)
    result = await db.execute(stmt)
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organização não encontrada.",
        )
    return tenant


@router.patch(
    "/{tenant_id}/status",
    response_model=TenantResponse,
    summary="Ativar ou desativar uma organização",
    dependencies=[Depends(verify_master_admin)],
)
async def toggle_tenant_status(
    tenant_id: uuid.UUID,
    is_active: bool,
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    """Modifica o status de ativação de uma organização."""
    stmt = select(Tenant).where(Tenant.id == tenant_id)
    result = await db.execute(stmt)
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organização não encontrada.",
        )
    tenant.is_active = is_active
    await db.commit()
    await db.refresh(tenant)
    invalidate_tenant_cache(tenant.api_key_hash)
    return tenant
