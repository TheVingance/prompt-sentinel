import time
from typing import Any
from fastapi import APIRouter
from sqlalchemy import text

from src.core.database import engine
from src.core.redis import get_redis

router = APIRouter(tags=["Health & Diagnostics"])


@router.get("/health")
async def health_check() -> dict[str, Any]:
    """Health check endpoint que valida conectividade assíncrona com Redis e PostgreSQL."""
    start_time = time.perf_counter()
    status_report: dict[str, Any] = {
        "status": "healthy",
        "timestamp": time.time(),
        "services": {},
    }

    # Verifica conexão com PostgreSQL
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        status_report["services"]["postgres"] = "online"
    except Exception as exc:
        status_report["status"] = "degraded"
        status_report["services"]["postgres"] = f"offline: {str(exc)}"

    # Verifica conexão com Redis
    try:
        redis_client = get_redis()
        if redis_client is not None and await redis_client.ping():
            status_report["services"]["redis"] = "online"
        else:
            status_report["status"] = "degraded"
            status_report["services"]["redis"] = "offline"
    except Exception as exc:
        status_report["status"] = "degraded"
        status_report["services"]["redis"] = f"offline: {str(exc)}"

    elapsed_ms = (time.perf_counter() - start_time) * 1000
    status_report["latency_ms"] = round(elapsed_ms, 2)
    return status_report
