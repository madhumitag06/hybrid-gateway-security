"""
Regression test suite to ensure UI asset integrity, CSS layout validity,
relative API resolution, SPA routing, and prevention of blank page regressions.
"""

from pathlib import Path
import re
from fastapi.testclient import TestClient
from backend.app.main import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def test_app_css_layout_and_syntax():
    """Verify src/App.css contains valid CSS without syntax corruptions like stray 'undefined'."""
    css_file = PROJECT_ROOT / "src" / "App.css"
    assert css_file.exists(), "src/App.css must exist"
    
    content = css_file.read_text(encoding="utf-8")
    
    # Must not start with stray tokens like undefined
    first_non_whitespace_line = next(line for line in content.splitlines() if line.strip())
    assert not first_non_whitespace_line.startswith("undefined"), (
        f"src/App.css starts with invalid token: {first_non_whitespace_line}"
    )
    
    # .app must specify display: flex
    assert re.search(r"\.app\s*\{[^}]*display:\s*flex;", content), (
        "src/App.css .app must have display: flex layout"
    )
    
    # main element must not have width: 0 or width: 0px (while min-width: 0 is allowed)
    main_match = re.search(r"main\s*\{([^}]+)\}", content)
    assert main_match, "main selector must be present in src/App.css"
    main_body = main_match.group(1)
    assert not re.search(r"(?<!-)\bwidth:\s*0(?:\s*px)?;", main_body), (
        f"main element has collapsing zero width: {main_body}"
    )
    assert "width: 100%" in main_body, "main element must expand to 100% width"


def test_api_service_base_url_defaults_to_relative():
    """Ensure src/services/api.ts defaults to relative URLs to avoid cross-port breakage."""
    api_file = PROJECT_ROOT / "src" / "services" / "api.ts"
    assert api_file.exists(), "src/services/api.ts must exist"
    
    content = api_file.read_text(encoding="utf-8")
    # Must default to empty string '' rather than hardcoded 'http://localhost:8000'
    assert "const API_BASE_URL = ENV_URL ? ENV_URL.replace(/\\/$/, '') : ''" in content, (
        "API_BASE_URL should default to relative path ''"
    )
    assert "const API_BASE_URL = ENV_URL ? ENV_URL.replace(/\\/$/, '') : 'http://localhost:8000'" not in content, (
        "src/services/api.ts should not hardcode http://localhost:8000 as default"
    )


def test_error_boundary_component_presence():
    """Verify ErrorBoundary exists and is integrated into App.tsx to catch view rendering exceptions."""
    eb_file = PROJECT_ROOT / "src" / "components" / "ErrorBoundary.tsx"
    assert eb_file.exists(), "src/components/ErrorBoundary.tsx must exist"
    
    app_tsx = PROJECT_ROOT / "src" / "App.tsx"
    app_content = app_tsx.read_text(encoding="utf-8")
    assert "ErrorBoundary" in app_content, "ErrorBoundary must be used in App.tsx"
    assert "<ErrorBoundary" in app_content, "ErrorBoundary must wrap views in App.tsx"


def test_dist_production_build_assets():
    """Verify dist directory exists, has index.html, JS and CSS bundles without syntax errors."""
    dist_dir = PROJECT_ROOT / "dist"
    assert dist_dir.exists(), "dist directory must exist from npm run build"
    
    index_html = dist_dir / "index.html"
    assert index_html.exists(), "dist/index.html must exist"
    html_content = index_html.read_text(encoding="utf-8")
    assert "<div id=\"root\"></div>" in html_content
    
    assets_dir = dist_dir / "assets"
    assert assets_dir.exists(), "dist/assets must exist"
    
    css_files = list(assets_dir.glob("*.css"))
    assert len(css_files) >= 1, "At least one CSS bundle must be generated"
    for css_file in css_files:
        assert css_file.stat().st_size > 1000, f"CSS bundle {css_file.name} is too small"
        css_text = css_file.read_text(encoding="utf-8")
        assert not css_text.startswith("undefined"), "Built CSS bundle must not start with 'undefined'"
        assert "display:flex" in css_text or "display: flex" in css_text
    
    js_files = list(assets_dir.glob("*.js"))
    assert len(js_files) >= 1, "At least one JS bundle must be generated"
    for js_file in js_files:
        assert js_file.stat().st_size > 10000, f"JS bundle {js_file.name} is too small"


def test_spa_client_routing_fallback():
    """Verify FastAPI backend serves index.html for non-API client-side navigation routes."""
    client = TestClient(app)
    
    # Standard API route returns JSON
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json().get("status") == "healthy"
    
    # Browser navigation to root "/" with Accept: text/html receives index.html
    root_html_resp = client.get("/", headers={"Accept": "text/html,application/xhtml+xml"})
    assert root_html_resp.status_code == 200
    assert "text/html" in root_html_resp.headers.get("content-type", "")
    assert "<div id=\"root\"></div>" in root_html_resp.text
    
    # Client-side SPA route (e.g. "/traffic" or "/simulation") receives index.html
    spa_resp = client.get("/traffic")
    assert spa_resp.status_code == 200
    assert "text/html" in spa_resp.headers.get("content-type", "")
    assert "<div id=\"root\"></div>" in spa_resp.text
