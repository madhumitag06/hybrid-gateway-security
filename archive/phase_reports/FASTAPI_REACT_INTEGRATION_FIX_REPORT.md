# FastAPI and React Frontend Integration Architecture Fix Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Frameworks:** FastAPI (Backend) + React 19 / Vite (Frontend)  
**Distribution Mode:** Standalone Production Windows Executable (`AdaptiveSecurityGateway.exe`)  
**Date:** November 15, 2026  
**Status:** ARCHITECTURE IMPLEMENTED & IN-PROCESS TESTED  

---

## 1. Executive Summary

This report documents the architectural corrections implemented in FastAPI to ensure the standalone Windows executable (`AdaptiveSecurityGateway.exe`) seamlessly serves the complete React Single-Page Application (SPA) alongside all backend REST APIs from a unified application origin on port 8000.

The implementation completely eliminates header-dependent branching at the root URL, enforces unconditional SPA delivery on `/`, mounts static production assets cleanly under `/assets/`, provides client-side SPA routing fallback, protects all REST endpoints under `/api/...` and `/docs`, and migrates root API discovery to `/api` and `/api/info`.

---

## 2. Integrated Routing & Asset Serving Architecture

```
                                      Incoming HTTP Request
                                                |
                                                v
                              +-----------------------------------+
                              |       FastAPI Router Pipeline     |
                              +-----------------------------------+
                                                |
                 +------------------------------+------------------------------+
                 |                              |                              |
                 v                              v                              v
           Route: "/api/*"             Route: "/docs", "/redoc"          Route: "/assets/*"
                 |                              |                              |
                 v                              v                              v
     FastAPI Backend Routers             Swagger / OpenAPI UI            StaticFiles Mount
     (JSON REST Endpoints)           (Interactive Documentation)       (dist/assets JS & CSS)
                 |                              |                              |
                 +------------------------------+------------------------------+
                                                |
                                                v
                               Route: "/" (Root URL Navigation)
                                                |
                                                v
                          Unconditional FileResponse(dist/index.html)
                                                |
                                                v
                          Route: "/{full_path:path}" (Catch-All SPA)
                                                |
                        Is full_path an existing file in dist?
                                   /                \
                             YES  /                  \  NO (Client-side React Route)
                                 v                    v
                        FileResponse(file)    FileResponse(dist/index.html)
```

---

## 3. Source-Code Modifications

### 3.1 Unconditional Root Dashboard Route (`backend/app/main.py`)
The header check (`if "text/html" in accept`) was completely removed. The root route now unconditionally serves `index.html`:

```python
_dist_dir = get_frontend_dist_dir()
if _dist_dir and (_dist_dir / "index.html").is_file():
    print(f"[+] Serving frontend distribution from: {_dist_dir}")
    _assets_dir = _dist_dir / "assets"
    if _assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(_assets_dir)), name="assets")

    # 1. Unconditionally serve the React production SPA index.html on root '/'
    @app.get("/", tags=["Dashboard SPA"], include_in_schema=False)
    def serve_root_dashboard():
        return FileResponse(_dist_dir / "index.html", media_type="text/html")

    # 2. SPA Catch-All for Client-Side Routing and Root Static Assets
    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa_or_static(full_path: str):
        # Do not intercept API, docs, redoc, openapi, or health routes
        if (
            full_path == "api"
            or full_path.startswith("api/")
            or full_path == "docs"
            or full_path.startswith("docs/")
            or full_path == "redoc"
            or full_path.startswith("redoc/")
            or full_path == "openapi.json"
            or full_path == "health"
            or full_path.startswith("health/")
            or full_path == "dashboard"
            or full_path == "search"
        ):
            raise HTTPException(status_code=404, detail="API route not found")

        # Check if requested path is a root static asset (e.g., favicon.svg, icons.svg)
        file_cand = _dist_dir / full_path
        if full_path and file_cand.is_file():
            return FileResponse(file_cand)

        # For all client-side React routes (e.g. /traffic, /aws-vpc, /events), serve index.html
        return FileResponse(_dist_dir / "index.html", media_type="text/html")
else:
    # Prominent diagnostic error handler if frontend assets were not built
    print("[!] CRITICAL ERROR: Frontend production distribution ('dist/index.html') not found!")

    @app.get("/", tags=["Root"])
    def root_missing_frontend():
        return HTMLResponse(
            status_code=500,
            content=(
                "<html><body style='font-family:sans-serif;padding:40px;background:#101713;color:#e6eed6;'>"
                "<h2>⚠️ Frontend Production Assets Missing</h2>"
                "<p>The standalone backend is running, but <code>dist/index.html</code> was not found.</p>"
                "<p>Please run <code>npm run build</code> and rebuild the standalone executable.</p>"
                "<p><a href='/docs' style='color:#74b9ff;'>View API Documentation (/docs)</a> | "
                "<a href='/api' style='color:#74b9ff;'>View API Info (/api)</a></p>"
                "</body></html>"
            ),
        )
```

### 3.2 Robust Multi-Tier Dist Resolution (`backend/app/config.py`)
`get_frontend_dist_dir` inspects candidate locations defensively across frozen PyInstaller runtimes and standard development environments:

```python
def get_frontend_dist_dir(require_exists: bool = False) -> Optional[Path]:
    candidates: List[Path] = []

    # 0. Explicit environment variable override
    explicit = os.getenv("FRONTEND_DIST_DIR")
    if explicit:
        candidates.append(Path(explicit).resolve())

    # 1. PyInstaller frozen runtime (_MEIPASS or _internal)
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "dist")
        exe_dir = Path(sys.executable).resolve().parent
        candidates.append(exe_dir / "_internal" / "dist")
        candidates.append(exe_dir / "dist")
        candidates.append(exe_dir.parent / "dist")

    # 2. Workspace root dist (development & standard python execution)
    ws_root = Path(__file__).resolve().parent.parent.parent
    candidates.append(ws_root / "dist")
    candidates.append(Path.cwd() / "dist")

    for cand in candidates:
        try:
            if cand.is_dir() and (cand / "index.html").is_file():
                return cand.resolve()
        except Exception:
            continue

    if require_exists:
        searched = ", ".join(str(c) for c in candidates)
        raise RuntimeError(
            f"Frontend production distribution ('dist/index.html') not found. Searched: {searched}."
        )

    return None
```

### 3.3 Explicit API Discovery Mapping
Root API discovery metadata is preserved at `/api` and `/api/info`:
```python
@app.get("/api", tags=["Root"])
@app.get("/api/info", tags=["Root"])
def root_api():
    """Returns gateway API discovery metadata."""
    return _get_root_info()
```

---

## 4. Automated In-Process Test Verification

An in-process TestClient test suite (`backend/tests/test_frontend_serving.py`) was executed without localhost network calls or external sockets:

```
backend/tests/test_frontend_serving.py::test_root_serves_spa_index_html PASSED [0.08s]
backend/tests/test_api_discovery_endpoint PASSED [0.03s]
backend/tests/test_api_health_endpoint PASSED [0.02s]
backend/tests/test_spa_client_side_routing_fallback PASSED [0.09s]
backend/tests/test_api_routes_not_swallowed_by_spa PASSED [0.02s]
============================== 5 passed in 3.75s ==============================
```

### Verified Behaviors:
1. `GET /` returns HTTP 200 with `Content-Type: text/html` and contains the React Single-Page Application container `<div id="root"></div>`.
2. `GET /api` and `GET /api/info` return HTTP 200 with JSON API discovery descriptors.
3. `GET /api/health` returns HTTP 200 with backend health status.
4. Client-side routes (`/traffic`, `/aws-vpc`, `/policies`, `/evaluation`, `/multi-cloud`) return HTTP 200 with `index.html`.
5. Non-existent `/api/v1/...` routes return HTTP 404 JSON errors and are not swallowed by the SPA fallback.
