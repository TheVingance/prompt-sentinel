from src.main import app


def test_readme_documented_endpoints_exist():
    """Valida via reflexão e schema OpenAPI que todos os endpoints documentados no README estão registrados."""
    registered_routes = set(app.openapi()["paths"].keys())

    expected_routes = [
        "/",
        "/dashboard",
        "/health",
        "/v1/chat/completions",
        "/v1/audit/incidents",
        "/v1/audit/metrics",
    ]

    for expected_path in expected_routes:
        assert (
            expected_path in registered_routes
        ), f"Rota documentada no README '{expected_path}' não foi encontrada na aplicação!"
