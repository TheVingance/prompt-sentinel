import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.routes.health import router as health_router
from src.api.routes.proxy import router as proxy_router
from src.core.config import settings
from src.core.database import close_db, init_db
from src.core.redis import close_redis_pool, init_redis_pool


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Gerencia o ciclo de vida dos recursos assíncronos (Redis e DB pools)."""
    # Inicialização
    try:
        await init_redis_pool()
    except Exception as exc:
        print(f"[Aviso] Redis não conectado na inicialização: {exc}")

    try:
        await init_db()
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
    process_time_ms = (time.perf_counter() - start_time) * 1000
    response.headers["X-Process-Time-Ms"] = f"{process_time_ms:.2f}"
    return response


# Registro de Rotas
app.include_router(health_router)
app.include_router(proxy_router)


@app.get("/", tags=["Root"])
async def root() -> dict[str, str]:
    return {
        "service": settings.PROJECT_NAME,
        "status": "operational",
        "docs": "/docs",
        "health": "/health",
    }
