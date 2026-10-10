from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["Interactive Dashboard"])

TEMPLATE_PATH = Path(__file__).resolve().parent.parent.parent / "templates" / "dashboard.html"


@router.get("/dashboard", response_class=HTMLResponse, summary="Dashboard Web Interativo de Segurança")
async def get_dashboard() -> HTMLResponse:
    """Retorna a interface web do PromptSentinel com Playground de ataques e telemetria de incidentes."""
    if TEMPLATE_PATH.exists():
        content = TEMPLATE_PATH.read_text(encoding="utf-8")
        return HTMLResponse(content=content)
    return HTMLResponse(content="<h1>Dashboard template not found</h1>", status_code=404)
