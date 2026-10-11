import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.api.routes.audit import router as audit_router
from src.api.routes.dashboard import router as dashboard_router
from src.api.routes.health import router as health_router
from src.api.routes.proxy import router as proxy_router
from src.api.routes.siem import router as siem_router
from src.api.routes.tenants import router as tenants_router
from src.core.config import settings
from src.core.database import async_session_factory, close_db, init_db
from src.core.metrics import (
    CONTENT_TYPE_LATEST,
    get_prometheus_metrics,
    sentinel_request_duration_seconds,
)
from src.core.redis import close_redis_pool, init_redis_pool
from src.services.seed import seed_attack_signatures


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Gerencia o ciclo de vida dos recursos assíncronos (Redis e DB pools)."""
    # Inicialização de Redis
    try:
        await init_redis_pool()
    except Exception as exc:
        print(f"[Aviso] Redis não conectado na inicialização: {exc}")

    # Inicialização de PostgreSQL & pgvector
    try:
        await init_db()
        async with async_session_factory() as session:
            inserted = await seed_attack_signatures(session)
            if inserted > 0:
                print(
                    f"[Sentinel Init] {inserted} assinaturas de ataque indexadas no pgvector com sucesso."
                )
    except Exception as exc:
        print(f"[Aviso] PostgreSQL não conectado na inicialização: {exc}")

    yield

    # Encerramento limpo dos pools
    await close_redis_pool()
    await close_db()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Gateway reverso de segurança e firewall de alta performance para LLMs.",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Calcula e adiciona o tempo de processamento em milissegundos para auditoria e benchmark."""
    start_time = time.perf_counter()
    response = await call_next(request)
    duration_s = time.perf_counter() - start_time
    process_time_ms = duration_s * 1000
    response.headers["X-Process-Time-Ms"] = f"{process_time_ms:.2f}"

    # Registra a latência no histograma Prometheus
    endpoint = request.url.path
    sentinel_request_duration_seconds.labels(endpoint=endpoint).observe(duration_s)
    return response


# Montagem de Arquivos Estáticos para a Interface Web
static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Registro de Rotas
app.include_router(dashboard_router)
app.include_router(health_router)
app.include_router(proxy_router)
app.include_router(audit_router)
app.include_router(tenants_router)
app.include_router(siem_router)


@app.get("/metrics", tags=["Observabilidade"])
async def metrics_endpoint() -> Response:
    """Exporta métricas corporativas no formato padrão do Prometheus para raspagem (scraping)."""
    return Response(
        content=get_prometheus_metrics(),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.get("/", tags=["Root"])
async def root() -> dict[str, str]:
    return {
        "service": settings.PROJECT_NAME,
        "status": "operational",
        "dashboard": "/dashboard",
        "docs": "/docs",
        "health": "/health",
        "metrics": "/metrics",
        "tenants": "/v1/tenants",
        "siem": "/v1/siem/events",
    }
