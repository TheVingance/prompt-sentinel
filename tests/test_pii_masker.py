import pytest
from httpx import ASGITransport, AsyncClient

from src.core.config import settings
from src.main import app
from src.pipeline.pii_masker import PIIMasker


@pytest.fixture
def masker() -> PIIMasker:
    return PIIMasker()


def test_mask_cpf(masker: PIIMasker):
    """Testa detecção e mascaramento de CPF brasileiro."""
    text = "O documento do cliente é 123.456.789-00 registrado em São Paulo."
    result = masker.mask(text)

    assert result.contains_pii is True
    assert "123.456.789-00" not in result.sanitized_text
    assert "[CPF_REDACTED_1]" in result.sanitized_text
    assert result.redaction_map["[CPF_REDACTED_1]"] == "123.456.789-00"


def test_mask_email(masker: PIIMasker):
    """Testa detecção e mascaramento de endereços de e-mail."""
    text = "Entre em contato via suporte@empresa.com.br ou admin@sentinel.ai."
    result = masker.mask(text)

    assert result.contains_pii is True
    assert "suporte@empresa.com.br" not in result.sanitized_text
    assert "admin@sentinel.ai" not in result.sanitized_text
    assert "[EMAIL_REDACTED_1]" in result.sanitized_text
    assert "[EMAIL_REDACTED_2]" in result.sanitized_text


def test_mask_credit_card_luhn_validation(masker: PIIMasker):
    """Testa se cartões válidos pelo algoritmo de Luhn são mascarados e números aleatórios ignorados."""
    # Cartão de teste com algoritmo de Luhn válido
    valid_card = "4532 0150 1234 5671"
    text_valid = f"Cobrar no cartão {valid_card} agora."
    result_valid = masker.mask(text_valid)
    assert valid_card not in result_valid.sanitized_text
    assert "[CREDIT_CARD_REDACTED_1]" in result_valid.sanitized_text

    # Sequência de 16 dígitos com checksum de Luhn inválido
    invalid_digits = "1234 5678 9012 3456"
    result_invalid = masker.mask(f"Número de protocolo {invalid_digits}")
    assert "[CREDIT_CARD_REDACTED_1]" not in result_invalid.sanitized_text


def test_mask_api_key(masker: PIIMasker):
    """Testa mascaramento de chaves secretas de API da OpenAI (incluindo sk-proj-)."""
    api_key = "sk-proj-abc1234567890abcdef1234567890"
    text = f"Minha chave é {api_key} para autenticação."
    result = masker.mask(text)

    assert api_key not in result.sanitized_text
    assert "[API_KEY_REDACTED_1]" in result.sanitized_text


def test_mask_phone_number(masker: PIIMasker):
    """Testa mascaramento de números de telefone com DDD."""
    phone = "(11) 98765-4321"
    text = f"Ligue para {phone} para suporte."
    result = masker.mask(text)

    assert phone not in result.sanitized_text
    assert "[PHONE_REDACTED_1]" in result.sanitized_text


def test_unmask_process(masker: PIIMasker):
    """Testa o processo de desanonimização revertendo os placeholders."""
    original_text = "Envie para contato@seguranca.org com CPF 111.222.333-44."
    mask_result = masker.mask(original_text)

    # Simula resposta do LLM usando os mesmos placeholders
    simulated_llm_response = (
        f"Confirmado! O e-mail {next(k for k, v in mask_result.redaction_map.items() if 'EMAIL' in k)} "
        f"e o documento {next(k for k, v in mask_result.redaction_map.items() if 'CPF' in k)} foram processados."
    )

    unmasked = masker.unmask(simulated_llm_response, mask_result.redaction_map)
    assert "contato@seguranca.org" in unmasked
    assert "111.222.333-44" in unmasked
    assert "_REDACTED_" not in unmasked


@pytest.mark.asyncio
async def test_proxy_integrates_pii_redaction_header():
    """Valida se o endpoint do proxy adiciona o header X-PII-Entities-Redacted."""
    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}
    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": "Meu email é dev@empresa.com e meu CPF é 999.888.777-66.",
            }
        ],
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/v1/chat/completions", json=payload, headers=headers)

    assert response.status_code == 200
    assert "X-PII-Entities-Redacted" in response.headers
    assert int(response.headers["X-PII-Entities-Redacted"]) == 2
