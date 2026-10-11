import time

import pytest
from httpx import ASGITransport, AsyncClient

from src.core.config import settings
from src.main import app
from src.pipeline.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    get_circuit_breaker,
    reset_all_circuit_breakers,
)
from src.pipeline.fallback_router import ResilientRouter


def test_circuit_breaker_initial_state():
    cb = CircuitBreaker("test-provider", CircuitBreakerConfig())
    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True
    assert cb.get_numeric_state() == 0


def test_circuit_breaker_trip_to_open_and_fast_fail():
    config = CircuitBreakerConfig(failure_threshold=3, cooldown_seconds=10.0)
    cb = CircuitBreaker("openai/gpt-4o", config)

    # 2 failures do not trip
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True

    # 3rd failure trips the circuit
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.get_numeric_state() == 2

    # Fast-fail while OPEN
    assert cb.allow_request() is False


def test_circuit_breaker_cooldown_to_half_open_and_recovery():
    config = CircuitBreakerConfig(
        failure_threshold=2,
        recovery_threshold=2,
        cooldown_seconds=0.1,  # 100ms for fast testing
    )
    cb = CircuitBreaker("anthropic/claude", config)

    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.allow_request() is False

    # Wait for cooldown to expire
    time.sleep(0.12)

    # Should transition to HALF_OPEN
    assert cb.allow_request() is True
    assert cb.state == CircuitState.HALF_OPEN
    assert cb.get_numeric_state() == 1

    # 1 success is not enough for recovery
    cb.record_success()
    assert cb.state == CircuitState.HALF_OPEN

    # 2nd success recovers back to CLOSED
    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.get_numeric_state() == 0


def test_circuit_breaker_half_open_failure_reopens():
    config = CircuitBreakerConfig(
        failure_threshold=1,
        cooldown_seconds=0.05,
    )
    cb = CircuitBreaker("mistral/large", config)
    cb.record_failure()
    assert cb.state == CircuitState.OPEN

    time.sleep(0.06)
    assert cb.allow_request() is True
    assert cb.state == CircuitState.HALF_OPEN

    # A failure in HALF_OPEN immediately re-opens
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.allow_request() is False


def test_circuit_breaker_registry():
    reset_all_circuit_breakers()
    cb1 = get_circuit_breaker("gpt-4o")
    cb2 = get_circuit_breaker("gpt-4o")
    cb3 = get_circuit_breaker("claude-3-5-sonnet")

    assert cb1 is cb2
    assert cb1 is not cb3


def test_resilient_router_chains():
    router = ResilientRouter()

    chain_gpt4 = router.get_fallback_chain("gpt-4o")
    assert chain_gpt4[0] == "gpt-4o"
    assert "gpt-4o-mini" in chain_gpt4

    chain_claude = router.get_fallback_chain("claude-3-5-sonnet")
    assert chain_claude[0] == "claude-3-5-sonnet"
    assert "gpt-4o-mini" in chain_claude

    # Unknown model gets default resilience chain
    chain_unknown = router.get_fallback_chain("unknown-llm-provider")
    assert chain_unknown[0] == "unknown-llm-provider"
    assert len(chain_unknown) > 1


def test_resilient_router_select_healthy_model():
    reset_all_circuit_breakers()
    router = ResilientRouter()

    primary_cb = get_circuit_breaker("gpt-4o", CircuitBreakerConfig(failure_threshold=1))
    # Trip primary
    primary_cb.record_failure()
    assert primary_cb.state == CircuitState.OPEN

    # Select healthy should route to next in chain
    healthy_model = router.select_healthy_model("gpt-4o")
    assert healthy_model != "gpt-4o"
    assert healthy_model == "gpt-4o-mini"


@pytest.mark.asyncio
async def test_proxy_outage_simulation_triggers_fallback():
    reset_all_circuit_breakers()
    transport = ASGITransport(app=app)
    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}

    payload = {
        "model": "gpt-4o-mini",
        "stream": False,
        "messages": [
            {
                "role": "user",
                "content": "Simulate provider outage: Test resilient high-availability failover.",
            }
        ],
    }

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/v1/chat/completions", json=payload, headers=headers)

    assert response.status_code == 200
    assert response.headers.get("X-Sentinel-Fallback-Triggered") == "true"
    assert response.headers.get("X-Sentinel-Provider-Routed") == "claude-3-5-sonnet"
    assert response.headers.get("X-Sentinel-Circuit-State") in ["CLOSED", "OPEN"]

    data = response.json()
    assert "choices" in data
    assert "Fallback Ativo" in data["choices"][0]["message"]["content"]


@pytest.mark.asyncio
async def test_proxy_normal_operation_circuit_closed():
    reset_all_circuit_breakers()
    transport = ASGITransport(app=app)
    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}

    payload = {
        "model": "gpt-4o-mini",
        "stream": False,
        "messages": [
            {
                "role": "user",
                "content": "Como otimizar consultas PostgreSQL com índices B-Tree e BRIN?",
            }
        ],
    }

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/v1/chat/completions", json=payload, headers=headers)

    assert response.status_code == 200
    assert response.headers.get("X-Sentinel-Fallback-Triggered") == "false"
    assert response.headers.get("X-Sentinel-Provider-Routed") == "gpt-4o-mini"
    assert response.headers.get("X-Sentinel-Circuit-State") == "CLOSED"


@pytest.mark.asyncio
async def test_proxy_streaming_fallback_headers():
    reset_all_circuit_breakers()
    transport = ASGITransport(app=app)
    headers = {"Authorization": f"Bearer {settings.SENTINEL_API_KEY}"}

    payload = {
        "model": "gpt-4o-mini",
        "stream": True,
        "messages": [
            {
                "role": "user",
                "content": "circuit breaker test: stream data with outage failover",
            }
        ],
    }

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/v1/chat/completions", json=payload, headers=headers)

    assert response.status_code == 200
    assert response.headers.get("X-Sentinel-Fallback-Triggered") == "true"
    assert response.headers.get("X-Sentinel-Provider-Routed") == "claude-3-5-sonnet"
