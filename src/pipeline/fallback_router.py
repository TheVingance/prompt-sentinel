"""Roteador resiliente com comutação de contingência automática (Multi-Model Fallback)."""

from dataclasses import dataclass
from typing import Any

from src.pipeline.circuit_breaker import CircuitState, get_circuit_breaker


@dataclass
class FallbackExecutionResult:
    """Resultado da tentativa de execução com contingência."""

    success: bool
    model_used: str
    fallback_triggered: bool
    circuit_state: CircuitState
    payload: dict[str, Any] | None = None
    error: str | None = None


class ResilientRouter:
    """Orquestra cadeias de fallback e isolamento de provedores instáveis."""

    DEFAULT_CHAINS: dict[str, list[str]] = {
        "gpt-4o": ["gpt-4o-mini", "mock-resilient"],
        "gpt-4o-mini": ["claude-3-5-sonnet", "mock-resilient"],
        "claude-3-5-sonnet": ["gpt-4o-mini", "mock-resilient"],
    }

    def __init__(self, custom_chains: dict[str, list[str]] | None = None) -> None:
        self.chains = custom_chains or self.DEFAULT_CHAINS

    def get_fallback_chain(self, primary_model: str) -> list[str]:
        """Retorna a sequência ordenada de modelos para comutação em caso de desastre."""
        candidates = self.chains.get(primary_model, ["mock-resilient"])
        # Garante que o modelo primário seja o primeiro, seguido pelos candidatos
        chain = [primary_model]
        for candidate in candidates:
            if candidate not in chain:
                chain.append(candidate)
        return chain

    def get_circuit_for_model(self, model: str):
        """Retorna a instância do Circuit Breaker responsável pelo modelo."""
        return get_circuit_breaker(model)

    def select_healthy_model(self, primary_model: str) -> str:
        """Percorre a cadeia de contingência e seleciona o primeiro modelo cujo circuito permite tráfego."""
        chain = self.get_fallback_chain(primary_model)
        for model in chain:
            cb = self.get_circuit_for_model(model)
            if cb.allow_request():
                return model
        return "mock-resilient"


# Instância global singleton do roteador resiliente
resilient_router = ResilientRouter()
