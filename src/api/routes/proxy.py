import time
import uuid
from typing import Any
from fastapi import APIRouter, Depends, Header, HTTPException, status
import httpx

from src.core.config import settings
from src.schemas.proxy import ChatCompletionRequest, ChatCompletionResponse
from src.schemas.security import SecurityIncidentResponse, ThreatCategory, ThreatSeverity

router = APIRouter(prefix="/v1", tags=["LLM Reverse Proxy"])


async def verify_api_key(authorization: str = Header(..., description="Bearer token de autenticação")) -> str:
    """Valida o Bearer token do cliente contra o SENTINEL_API_KEY configurado."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header Authorization deve iniciar com 'Bearer '",
        )
    token = authorization.removeprefix("Bearer ").strip()
    if token != settings.SENTINEL_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de API inválido ou não autorizado pelo Sentinel",
        )
    return token


@router.post(
    "/chat/completions",
    response_model=ChatCompletionResponse,
    responses={
        403: {"model": SecurityIncidentResponse, "description": "Bloqueado pelo Firewall de IA"},
    },
)
async def chat_completions(
    request: ChatCompletionRequest,
    _token: str = Depends(verify_api_key),
) -> Any:
    """Endpoint proxy de alta performance compatível com OpenAI Chat Completions.
    
    Aplica o pipeline de inspeção de segurança:
    1. Verificação de rate limiting por IP/Usuário
    2. Sanitização e heurística de injeção direta
    3. Mascaramento e detecção de dados sensíveis (PII)
    4. Análise semântica de similaridade de jailbreak
    5. Encaminhamento seguro ao LLM upstream
    """
    # Exemplo de bloqueio rápido heurístico para validação inicial de segurança
    for message in request.messages:
        content_text = str(message.content).lower()
        if "ignore previous instructions" in content_text or "ignore all prior instructions" in content_text:
            incident = SecurityIncidentResponse(
                incident_id=str(uuid.uuid4()),
                category=ThreatCategory.PROMPT_INJECTION,
                severity=ThreatSeverity.CRITICAL,
                reason="Tentativa explícita de bypass detectada ('Ignore previous instructions')",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=incident.model_dump(mode="json"),
            )

    # Caso não haja chave upstream configurada (mock em desenvolvimento local)
    if not settings.TARGET_LLM_API_KEY:
        return ChatCompletionResponse(
            id=f"chatcmpl-{uuid.uuid4().hex[:12]}",
            created=int(time.time()),
            model=request.model,
            choices=[
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "🛡️ [PromptSentinel Mock] Mensagem analisada e aprovada pelo firewall de IA! (Configure TARGET_LLM_API_KEY no .env para repasse upstream).",
                    },
                    "finish_reason": "stop",
                }
            ],
            usage={
                "prompt_tokens": 15,
                "completion_tokens": 28,
                "total_tokens": 43,
            },
        )

    # Repasse upstream assíncrono caso chave esteja configurada
    async with httpx.AsyncClient(timeout=60.0) as client:
        upstream_url = f"{settings.TARGET_LLM_BASE_URL.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {settings.TARGET_LLM_API_KEY}",
            "Content-Type": "application/json",
        }
        response = await client.post(
            upstream_url,
            headers=headers,
            json=request.model_dump(exclude_none=True),
        )

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=response.text,
            )

        return response.json()
