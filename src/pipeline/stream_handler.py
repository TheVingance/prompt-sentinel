import asyncio
import json
import logging
import time
import uuid
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.metrics import sentinel_threats_blocked_total
from src.models.security import AuditIncident
from src.pipeline.pii_masker import pii_masker

logger = logging.getLogger(__name__)


class StreamInspector:
    """Consome e inspeciona tokens gerados por LLMs em tempo real via Server-Sent Events (SSE).

    Aplica a técnica defensiva In-Flight Safety Severing: caso o modelo alucine
    ou comece a vazar credenciais/PII sensíveis durante o fluxo, a conexão é interrompida imediatamente.
    """

    def __init__(
        self,
        model_name: str = "gpt-4o",
        session: AsyncSession | None = None,
        client_ip: str = "127.0.0.1",
        canary_token: str | None = None,
    ):
        self.model_name = model_name
        self.session = session
        self.client_ip = client_ip
        self.canary_token = canary_token
        self.stream_id = f"chatcmpl-stream-{uuid.uuid4().hex[:12]}"
        self.buffer = ""
        self.severed = False

    def _format_chunk(self, content: str, finish_reason: str | None = None) -> str:
        """Formata um chunk SSE conforme especificação oficial da OpenAI."""
        payload = {
            "id": self.stream_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": self.model_name,
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": content} if content else {},
                    "finish_reason": finish_reason,
                }
            ],
        }
        return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

    def _check_in_flight_violation(self, text_window: str) -> bool:
        """Avalia se a janela de texto em voo contém vazamento de dados críticos."""
        # Avalia cartões de crédito com validação algorítmica Luhn e chaves de API secretas
        mask_res = pii_masker.mask(text_window)
        if mask_res.contains_pii:
            for entity in mask_res.redaction_map:
                if "CREDIT_CARD" in entity or "API_KEY" in entity:
                    return True
        return False

    async def _record_severing_incident(
        self,
        leaked_sample: str,
        reason: str = "In-Flight Safety Severing: O modelo upstream começou a emitir dados sensíveis não autorizados",
        pattern: str = "Credit Card / API Key Exfiltration",
        category: str = "pii_leakage",
    ) -> str:
        """Registra o incidente de corte forçado na trilha de auditoria."""
        incident_id = str(uuid.uuid4())
        if self.session is not None:
            try:
                incident = AuditIncident(
                    id=uuid.UUID(incident_id),
                    client_ip=self.client_ip,
                    threat_category=category,
                    threat_severity="critical",
                    reason=reason,
                    matched_pattern=pattern,
                    similarity_score=1.0,
                    sanitized_prompt_sample=leaked_sample[:500],
                )
                self.session.add(incident)
                await self.session.commit()
            except Exception as e:
                logger.error(f"Erro ao registrar incidente de streaming severing: {e}")
        return incident_id

    async def inspect_and_stream(
        self,
        raw_tokens_generator: AsyncGenerator[str, None],
    ) -> AsyncGenerator[str, None]:
        """Consome o gerador assíncrono de tokens, avalia em buffer e emite SSE."""
        full_generated_text = []

        try:
            async for token in raw_tokens_generator:
                self.buffer += token
                full_generated_text.append(token)

                # 1. Checagem de Canary Token Leak em voo
                if self.canary_token and self.canary_token in self.buffer:
                    self.severed = True
                    sentinel_threats_blocked_total.labels(
                        category="system_prompt_extraction",
                        severity="critical",
                    ).inc()
                    incident_id = await self._record_severing_incident(
                        self.buffer,
                        reason=f"In-Flight Canary Token Severing: O modelo vazou o canary token secreto '{self.canary_token}'",
                        pattern="Canary Token Exfiltration",
                        category="system_prompt_extraction",
                    )
                    sever_msg = (
                        f"\n\n🚨 [TRANSMISSÃO INTERROMPIDA PELO PROMPT SENTINEL: "
                        f"Roubo de System Prompt interceptado via Canary Token (Incident ID: {incident_id})]\n"
                    )
                    yield self._format_chunk(content=sever_msg, finish_reason="security_override")
                    yield "data: [DONE]\n\n"
                    return

                # 2. Mantém uma janela deslizante dos últimos 150 caracteres para avaliação DLP
                window = self.buffer[-150:]
                if self._check_in_flight_violation(window):
                    self.severed = True
                    sentinel_threats_blocked_total.labels(
                        category="pii_leakage",
                        severity="critical",
                    ).inc()
                    incident_id = await self._record_severing_incident(self.buffer)

                    # Emite mensagem de interrupção de segurança em voo
                    sever_msg = (
                        f"\n\n🚨 [TRANSMISSÃO INTERROMPIDA PELO PROMPT SENTINEL: "
                        f"Violação de segurança detectada em voo (Incident ID: {incident_id})]\n"
                    )
                    yield self._format_chunk(content=sever_msg, finish_reason="security_override")
                    yield "data: [DONE]\n\n"
                    return

                yield self._format_chunk(content=token)

            # Encerramento normal do stream
            if not self.severed:
                yield self._format_chunk(content="", finish_reason="stop")
                yield "data: [DONE]\n\n"

        except Exception as exc:
            logger.error(f"Erro no processamento do stream: {exc}")
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"
            yield "data: [DONE]\n\n"


async def mock_token_generator(message: str) -> AsyncGenerator[str, None]:
    """Simula a emissão gradual de tokens para testes e desenvolvimento local."""
    words = message.split(" ")
    for i, word in enumerate(words):
        token = word if i == len(words) - 1 else f"{word} "
        await asyncio.sleep(0.015)  # Latência realista de 15ms entre tokens
        yield token


async def create_cached_stream_generator(
    cached_content: str,
    model: str = "gpt-4o",
) -> AsyncGenerator[str, None]:
    """Gera um fluxo SSE simulado em altíssima velocidade para respostas em Cache HIT."""
    stream_id = f"chatcmpl-cache-{uuid.uuid4().hex[:10]}"
    words = cached_content.split(" ")

    for i, word in enumerate(words):
        token = word if i == len(words) - 1 else f"{word} "
        chunk = {
            "id": stream_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": token},
                    "finish_reason": None,
                }
            ],
        }
        yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
        await asyncio.sleep(0.008)

    # Chunk final
    final_chunk = {
        "id": stream_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }
        ],
    }
    yield f"data: {json.dumps(final_chunk, ensure_ascii=False)}\n\n"
    yield "data: [DONE]\n\n"
