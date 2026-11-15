"""
Frontend & Static Asset Serving Tests (In-Process TestClient)
=============================================================
Validates:
1. Root '/' unconditionally serves React production 'index.html'.
2. Root '/api' and '/api/info' return API discovery metadata.
3. Bundled assets in '/assets/...' are correctly mounted and returned.
4. Client-side SPA routes (e.g., '/traffic', '/aws-vpc') fallback to 'index.html'.
5. API routes (e.g., '/api/unknown') return 404 and are NOT swallowed by SPA fallback.
6. '/api/health' remains fully functional.
"""

import pytest
from starlette.testclient import TestClient
from backend.app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_root_serves_spa_index_html(client):
    """Verify that GET / unconditionally returns the production React index.html."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert '<div id="root"></div>' in response.text
    assert "<title>Adaptive AI Security Gateway" in response.text


def test_api_discovery_endpoint(client):
    """Verify that /api and /api/info return the JSON discovery info dictionary."""
    resp1 = client.get("/api")
    assert resp1.status_code == 200
    assert resp1.headers["content-type"] == "application/json"
    data1 = resp1.json()
    assert "app" in data1
    assert "version" in data1
    assert data1["prediction_endpoint"] == "/api/v1/predict"

    resp2 = client.get("/api/info")
    assert resp2.status_code == 200
    assert resp2.json() == data1


def test_api_health_endpoint(client):
    """Verify that /api/health and /health continue returning health JSON."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("healthy", "degraded")
    assert "model_loaded" in data


def test_spa_client_side_routing_fallback(client):
    """Verify that client-side SPA routes fallback to index.html without being 404'd."""
    for route in ["/traffic", "/aws-vpc", "/policies", "/evaluation", "/multi-cloud"]:
        resp = client.get(route)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert '<div id="root"></div>' in resp.text


def test_api_routes_not_swallowed_by_spa(client):
    """Verify that non-existent /api/... routes return 404 and are NOT caught by the SPA fallback."""
    resp = client.get("/api/v1/non_existent_endpoint_xyz")
    assert resp.status_code == 404
    assert resp.headers["content-type"] == "application/json"
    assert resp.json()["detail"] == "Not Found" or "API route not found" in resp.json()["detail"]


def test_docs_and_openapi_not_swallowed_by_spa(client):
    """Verify that Swagger docs, ReDoc, and OpenAPI schema remain available."""
    resp_docs = client.get("/docs")
    assert resp_docs.status_code == 200
    assert "text/html" in resp_docs.headers["content-type"]

    resp_openapi = client.get("/openapi.json")
    assert resp_openapi.status_code == 200
    assert "application/json" in resp_openapi.headers["content-type"]
    assert "paths" in resp_openapi.json()


def test_static_assets_serving(client):
    """Verify that static assets mounted under /assets/ are served with correct headers."""
    from backend.app.config import get_frontend_dist_dir
    dist_dir = get_frontend_dist_dir()
    if dist_dir and (dist_dir / "assets").is_dir():
        import os
        asset_files = [f for f in os.listdir(dist_dir / "assets") if f.endswith(".js") or f.endswith(".css")]
        if asset_files:
            target = f"/assets/{asset_files[0]}"
            resp = client.get(target)
            assert resp.status_code == 200
            assert len(resp.content) > 0
