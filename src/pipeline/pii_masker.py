import re
from dataclasses import dataclass, field
from enum import StrEnum


class PIIType(StrEnum):
    CPF = "CPF"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CREDIT_CARD = "CREDIT_CARD"
    API_KEY = "API_KEY"


def _is_luhn_valid(card_number: str) -> bool:
    """Valida número de cartão de crédito através do algoritmo de Luhn (Módulo 10)."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


@dataclass
class PIIMaskingResult:
    sanitized_text: str
    redaction_map: dict[str, str] = field(default_factory=dict)
    entity_counts: dict[str, int] = field(default_factory=dict)

    @property
    def contains_pii(self) -> bool:
        return len(self.redaction_map) > 0

    @property
    def total_redacted(self) -> int:
        return sum(self.entity_counts.values())


class PIIMasker:
    """Mecanismo de alta performance para detecção e anonimização de dados sensíveis (PII).

    Protege contra vazamento de dados confidenciais (OWASP LLM02) e conformidade LGPD/GDPR.
    """

    # Expressões regulares compiladas para máxima performance (< 1ms por prompt)
    EMAIL_REGEX = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    )

    CPF_REGEX = re.compile(
        r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"
    )

    # Telefone com DDD obrigatório (com ou sem código do país +55)
    PHONE_REGEX = re.compile(
        r"\b(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)(?:9\s?)?\d{4}[-.\s]?\d{4}\b"
    )

    # Formatos de 16 dígitos separados por espaço/traço ou 13 a 19 dígitos contínuos
    CREDIT_CARD_REGEX = re.compile(
        r"\b(?:\d{4}[-\s]){3}\d{4}\b|\b\d{13,19}\b"
    )

    # API keys da OpenAI (incluindo sk-proj-), GitHub tokens, Slack e JWT
    API_KEY_REGEX = re.compile(
        r"\b(?:sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[a-zA-Z0-9]{10,48}|Bearer\s+ey[a-zA-Z0-9._\-]+)\b"
    )

    def mask(self, text: str) -> PIIMaskingResult:
        """Anonimiza entidades sensíveis no texto e gera o mapa de correspondência."""
        if not text:
            return PIIMaskingResult(sanitized_text=text)

        sanitized = text
        redaction_map: dict[str, str] = {}
        entity_counts: dict[str, int] = {pii_type.value: 0 for pii_type in PIIType}

        # 1. API Keys e Segredos
        def replace_api_key(match: re.Match) -> str:
            val = match.group(0)
            entity_counts[PIIType.API_KEY.value] += 1
            idx = entity_counts[PIIType.API_KEY.value]
            placeholder = f"[{PIIType.API_KEY.value}_REDACTED_{idx}]"
            redaction_map[placeholder] = val
            return placeholder

        sanitized = self.API_KEY_REGEX.sub(replace_api_key, sanitized)

        # 2. Cartões de crédito (aplica validação de Luhn para eliminar falsos positivos)
        def replace_card(match: re.Match) -> str:
            val = match.group(0)
            cleaned = re.sub(r"[\s-]", "", val)
            if _is_luhn_valid(cleaned):
                entity_counts[PIIType.CREDIT_CARD.value] += 1
                idx = entity_counts[PIIType.CREDIT_CARD.value]
                placeholder = f"[{PIIType.CREDIT_CARD.value}_REDACTED_{idx}]"
                redaction_map[placeholder] = val
                return placeholder
            return val

        sanitized = self.CREDIT_CARD_REGEX.sub(replace_card, sanitized)

        # 3. E-mails
        def replace_email(match: re.Match) -> str:
            val = match.group(0)
            entity_counts[PIIType.EMAIL.value] += 1
            idx = entity_counts[PIIType.EMAIL.value]
            placeholder = f"[{PIIType.EMAIL.value}_REDACTED_{idx}]"
            redaction_map[placeholder] = val
            return placeholder

        sanitized = self.EMAIL_REGEX.sub(replace_email, sanitized)

        # 4. CPF (formato 000.000.000-00 ou 11 dígitos com pontuação)
        def replace_cpf(match: re.Match) -> str:
            val = match.group(0)
            raw = re.sub(r"\D", "", val)
            if len(raw) == 11 and val not in redaction_map.values():
                entity_counts[PIIType.CPF.value] += 1
                idx = entity_counts[PIIType.CPF.value]
                placeholder = f"[{PIIType.CPF.value}_REDACTED_{idx}]"
                redaction_map[placeholder] = val
                return placeholder
            return val

        sanitized = self.CPF_REGEX.sub(replace_cpf, sanitized)

        # 5. Telefones
        def replace_phone(match: re.Match) -> str:
            val = match.group(0)
            entity_counts[PIIType.PHONE.value] += 1
            idx = entity_counts[PIIType.PHONE.value]
            placeholder = f"[{PIIType.PHONE.value}_REDACTED_{idx}]"
            redaction_map[placeholder] = val
            return placeholder

        sanitized = self.PHONE_REGEX.sub(replace_phone, sanitized)

        # Limpa contagens com 0 para saída concisa
        filtered_counts = {k: v for k, v in entity_counts.items() if v > 0}

        return PIIMaskingResult(
            sanitized_text=sanitized,
            redaction_map=redaction_map,
            entity_counts=filtered_counts,
        )

    def unmask(self, text: str, redaction_map: dict[str, str]) -> str:
        """Restaura os valores originais no texto de resposta substituindo os placeholders."""
        if not text or not redaction_map:
            return text
        result = text
        for placeholder, original in redaction_map.items():
            result = result.replace(placeholder, original)
        return result


pii_masker = PIIMasker()
