"""Mecanismo de Circuit Breaker para tolerância a falhas e alta disponibilidade de LLMs."""

import time
from dataclasses import dataclass
from enum import StrEnum


class CircuitState(StrEnum):
    """Estados operacionais do Circuit Breaker."""

    CLOSED = "closed"
    HALF_OPEN = "half_open"
    OPEN = "open"


@dataclass
class CircuitBreakerConfig:
    """Parâmetros de controle e sensibilidade do Circuit Breaker."""

    failure_threshold: int = 3
    cooldown_seconds: float = 30.0
    recovery_threshold: int = 2


class CircuitBreaker:
    """Implementa o padrão Martin Fowler para isolar provedores instáveis e evitar degradação em cascata."""

    def __init__(self, name: str, config: CircuitBreakerConfig | None = None) -> None:
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state: CircuitState = CircuitState.CLOSED
        self._failure_count: int = 0
        self._success_count: int = 0
        self._last_state_change: float = time.monotonic()

    @property
    def state(self) -> CircuitState:
        """Calcula o estado atual considerando o temporizador de resfriamento (cooldown)."""
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._last_state_change
            if elapsed >= self.config.cooldown_seconds:
                self._state = CircuitState.HALF_OPEN
                self._last_state_change = time.monotonic()
                self._success_count = 0
        return self._state

    def allow_request(self) -> bool:
        """Determina se uma nova requisição pode ser despachada para o provedor primário."""
        current_state = self.state
        if current_state == CircuitState.CLOSED:
            return True
        if current_state == CircuitState.HALF_OPEN:
            # Em HALF_OPEN, permite requisições canário para sondar o retorno da saúde
            return True
        # OPEN: Fast-fail imediato
        return False

    def record_success(self) -> None:
        """Registra uma chamada concluída com sucesso pelo provedor."""
        current_state = self.state
        if current_state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.config.recovery_threshold:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._success_count = 0
                self._last_state_change = time.monotonic()
        elif current_state == CircuitState.CLOSED:
            self._failure_count = 0

    def record_failure(self) -> None:
        """Registra uma falha (HTTP 5xx, 429 ou Timeout de rede)."""
        current_state = self.state
        if current_state == CircuitState.HALF_OPEN:
            # Se falhou durante o teste canário, volta imediatamente para OPEN
            self._state = CircuitState.OPEN
            self._last_state_change = time.monotonic()
            self._success_count = 0
        elif current_state == CircuitState.CLOSED:
            self._failure_count += 1
            if self._failure_count >= self.config.failure_threshold:
                self._state = CircuitState.OPEN
                self._last_state_change = time.monotonic()

    def force_state(self, new_state: CircuitState) -> None:
        """Força manualmente um estado para testes de resiliência e simulações."""
        self._state = new_state
        self._last_state_change = time.monotonic()
        if new_state == CircuitState.CLOSED:
            self._failure_count = 0
            self._success_count = 0

    def get_numeric_state(self) -> int:
        """Retorna código numérico para exportação no Prometheus (0=CLOSED, 1=HALF_OPEN, 2=OPEN)."""
        current_state = self.state
        if current_state == CircuitState.CLOSED:
            return 0
        if current_state == CircuitState.HALF_OPEN:
            return 1
        return 2


# Registro global de circuit breakers indexados por nome de provedor/modelo
_breakers: dict[str, CircuitBreaker] = {}


def get_circuit_breaker(name: str, config: CircuitBreakerConfig | None = None) -> CircuitBreaker:
    """Recupera ou instancia um Circuit Breaker com escopo unívoco por provedor."""
    if name not in _breakers:
        _breakers[name] = CircuitBreaker(name, config)
    return _breakers[name]


def reset_all_circuit_breakers() -> None:
    """Limpa o registro global de circuit breakers (utilizado em suites de testes)."""
    _breakers.clear()
