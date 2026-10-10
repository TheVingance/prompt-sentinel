import time
import uuid
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.database import get_db_session
from src.pipeline.pii_masker import pii_masker
from src.pipeline.rate_limiter import RateLimitResult, check_rate_limit
from src.pipeline.semantic_detector import semantic_detector
from src.schemas.proxy import ChatCompletionRequest, ChatCompletionResponse
from src.schemas.security import (
    SecurityIncidentResponse,
    ThreatCategory,
    ThreatSeverity,
)

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
        429: {"description": "Taxa de requisições excedida (Rate limit)"},
    },
)
async def chat_completions(
    request_data: ChatCompletionRequest,
    raw_request: Request,
    response: Response,
    _token: str = Depends(verify_api_key),
    rate_limit: RateLimitResult = Depends(check_rate_limit),
    db: AsyncSession = Depends(get_db_session),
) -> Any:
    """Endpoint proxy de alta performance compatível com OpenAI Chat Completions.

    Aplica o pipeline completo de inspeção de segurança:
    1. Verificação de rate limiting por IP/Usuário
    2. Sanitização e heurística de injeção direta
    3. Mascaramento e detecção de dados sensíveis (PII)
    4. Análise semântica de similaridade de jailbreak no pgvector
    5. Encaminhamento seguro ao LLM upstream
    """
    # 1. Injeta cabeçalhos informativos de Rate Limit na resposta
    response.headers["X-RateLimit-Limit"] = str(rate_limit.limit)
    response.headers["X-RateLimit-Remaining"] = str(rate_limit.remaining)
    response.headers["X-RateLimit-Reset"] = str(rate_limit.reset_seconds)

    forwarded = raw_request.headers.get("X-Forwarded-For")
    client_ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (raw_request.client.host if raw_request.client else "127.0.0.1")
    )

    # 2. Pipeline de Sanitização & PII Masking
    global_redaction_map: dict[str, str] = {}
    total_pii_redacted = 0

    for message in request_data.messages:
        if isinstance(message.content, str):
            # Validação heurística rápida contra bypass explícito (Fast-path)
            content_lower = message.content.lower()
            if "ignore previous instructions" in content_lower or "ignore all prior instructions" in content_lower:
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

            # Aplica mascaramento de dados sensíveis (DLP)
            mask_result = pii_masker.mask(message.content)
            if mask_result.contains_pii:
                message.content = mask_result.sanitized_text
                global_redaction_map.update(mask_result.redaction_map)
                total_pii_redacted += mask_result.total_redacted

            # Análise Semântica de Injeção no pgvector (Slow-path inteligente)
            is_threat, incident_resp = await semantic_detector.analyze(
                text=message.content,
                session=db,
                client_ip=client_ip,
            )
            if is_threat and incident_resp is not None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=incident_resp.model_dump(mode="json"),
                )

    # Injeta telemetria de PIIs interceptados
    if total_pii_redacted > 0:
        response.headers["X-PII-Entities-Redacted"] = str(total_pii_redacted)

    # 3. Caso não haja chave upstream configurada (mock em desenvolvimento local)
    if not settings.TARGET_LLM_API_KEY:
        mock_reply = "🛡️ [PromptSentinel Mock] Mensagem analisada e aprovada pelo firewall de IA!"
        if global_redaction_map:
            first_placeholder = next(iter(global_redaction_map))
            mock_reply += f" Entidade detectada: {first_placeholder}"

        unmasked_reply = pii_masker.unmask(mock_reply, global_redaction_map)

        return ChatCompletionResponse(
            id=f"chatcmpl-{uuid.uuid4().hex[:12]}",
            created=int(time.time()),
            model=request_data.model,
            choices=[
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": unmasked_reply,
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

    # 4. Repasse upstream assíncrono caso chave esteja configurada
    async with httpx.AsyncClient(timeout=60.0) as client:
        upstream_url = f"{settings.TARGET_LLM_BASE_URL.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {settings.TARGET_LLM_API_KEY}",
            "Content-Type": "application/json",
        }
        res = await client.post(
            upstream_url,
            headers=headers,
            json=request_data.model_dump(exclude_none=True),
        )

        if res.status_code != 200:
            raise HTTPException(
                status_code=res.status_code,
                detail=res.text,
            )

        payload = res.json()
        if global_redaction_map and "choices" in payload:
            for choice in payload["choices"]:
                if "message" in choice and "content" in choice["message"]:
                    choice["message"]["content"] = pii_masker.unmask(
                        choice["message"]["content"],
                        global_redaction_map,
                    )

        return payload
