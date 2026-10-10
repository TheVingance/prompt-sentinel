import re
from dataclasses import dataclass

from src.pipeline.canary import canary_manager
from src.pipeline.pii_masker import pii_masker
from src.schemas.security import ThreatCategory, ThreatSeverity

# Assinaturas conhecidas de comandos de execução remota de código e reverse shells
DANGEROUS_CODE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+", re.IGNORECASE),
        "Bash Network Reverse Shell (/dev/tcp)",
    ),
    (
        re.compile(r"nc\s+.*-e\s+(/bin/sh|/bin/bash|cmd\.exe|powershell)", re.IGNORECASE),
        "Netcat Inbound/Outbound Shell (-e)",
    ),
    (
        re.compile(
            r"powershell(\.exe)?\s+(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE
        ),
        "PowerShell Encoded Payload Execution",
    ),
    (
        re.compile(r"rm\s+-rf\s+/\s*(--no-preserve-root)?", re.IGNORECASE),
        "Destructive Root Command (rm -rf /)",
    ),
]


@dataclass
class OutputGuardrailResult:
    """Resultado da inspeção de saída do modelo."""

    is_threat: bool
    sanitized_text: str
    threat_category: ThreatCategory | None = None
    threat_severity: ThreatSeverity | None = None
    threat_reason: str | None = None


class OutputGuardrail:
    """Aplica inspeção e higienização em tempo real na resposta gerada pelo modelo upstream (Outbound Guardrails)."""

    def inspect_and_sanitize(
        self,
        text: str,
        canary_token: str | None = None,
    ) -> OutputGuardrailResult:
        """Avalia se a saída gerada contém vazamento de Canary Token, shellcode perigoso ou PII não autorizado."""
        if not text:
            return OutputGuardrailResult(is_threat=False, sanitized_text="")

        # 1. Verificação de Honeypot / Canary Token Leak (OWASP LLM07)
        if canary_token and canary_manager.detect_leak(text, canary_token):
            return OutputGuardrailResult(
                is_threat=True,
                sanitized_text="",
                threat_category=ThreatCategory.SYSTEM_PROMPT_EXTRACTION,
                threat_severity=ThreatSeverity.CRITICAL,
                threat_reason=(
                    f"Violação Crítica de Integridade: O modelo expôs o Canary Token secreto '{canary_token}', "
                    f"confirmando ataque de extração de system prompt."
                ),
            )

        # 2. Verificação de Comandos e Shells Destrutivos
        for pattern, label in DANGEROUS_CODE_PATTERNS:
            if pattern.search(text):
                return OutputGuardrailResult(
                    is_threat=True,
                    sanitized_text="",
                    threat_category=ThreatCategory.HARMFUL_CONTENT,
                    threat_severity=ThreatSeverity.CRITICAL,
                    threat_reason=f"Bloqueio de Saída: O modelo gerou código potencialmente malicioso ('{label}').",
                )

        # 3. Mascaramento de dados sensíveis na saída (DLP Outbound)
        mask_result = pii_masker.mask(text)
        sanitized_text = mask_result.sanitized_text if mask_result.contains_pii else text

        return OutputGuardrailResult(
            is_threat=False,
            sanitized_text=sanitized_text,
        )


output_guardrail = OutputGuardrail()
