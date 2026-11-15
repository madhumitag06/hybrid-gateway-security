# PHASE 8 ROOT-CAUSE INVESTIGATION REPORT: ROOT JSON SERVING FAILURE

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Deliverable:** Phase 8 Root-Cause Analysis  
**Date:** November 15, 2026  
**Status:** RESOLVED & PERMANENTLY MITIGATED  

---

## 1. Executive Summary

When attempting to access the standalone Adaptive Security Gateway dashboard at `http://localhost:8000`, the web browser consistently displayed a raw JSON response:

```json
{
  "app": "Adaptive Hybrid Cloud Security Gateway",
  "version": "1.0.0",
  "status": "online",
  "database": "PostgreSQL Connected",
  "docs": "/docs",
  "health": "/api/health",
  "prediction_endpoint": "/api/v1/predict",
  "events_endpoint": "/api/v1/events",
  "ingestion_endpoint": "/api/v1/ingest/pcap",
  "enforcement_endpoint": "/api/v1/enforcement/rules"
}
```

This occurred even after verified backend source code changes in `backend/app/main.py` explicitly removed all JSON root handlers in favor of unconditionally serving `dist/index.html`.

A comprehensive forensic network and process investigation uncovered the definitive **smoking gun**:

1. The raw JSON response was **never produced by `AdaptiveSecurityGateway.exe`**.
2. The response was produced by an 11-day-old Docker container named **`hybrid-lab-gateway-api`** (`container_id: 3b80f2c684ed`) launched from `deployment/hybrid-lab/compose.yaml`.
3. In `compose.yaml`, the container service had port mapping `"${GATEWAY_API_PORT:-8000}:8000"`, binding `0.0.0.0:8000` and `[::]:8000` (IPv6).
4. Modern web browsers (Google Chrome, Microsoft Edge) resolve `localhost` to IPv6 `[::1]` by default.
5. Consequently, any browser request to `http://localhost:8000` was routed over IPv6 into the Docker container `hybrid-lab-gateway-api`, which was running an outdated image where `/` returned the raw JSON metadata.
6. When `AdaptiveSecurityGateway.exe` was launched on Windows, it attempted to bind to `127.0.0.1:8000`. The port was already held by Docker's Windows proxy (`com.docker.backend.exe` / `vpnkit`), causing Uvicorn to encounter `[WinError 10048] Only one usage of each socket address is normally permitted` and fail silently.

---

## 2. Forensic Evidence & Technical Proof

### 2.1 The Container and Process Audit
Running a targeted process and socket query revealed:
- `docker ps --filter "name=gateway-api"`:
  ```
  CONTAINER ID   IMAGE                 COMMAND                  PORTS
  3b80f2c684ed   hybrid-lab-gateway-api "uvicorn app.main:app…"  0.0.0.0:8000->8000/tcp, :::8000->8000/tcp
  ```
- Created: 11 days ago (`2026-11-04 18:35:48 +0530 IST`).
- `docker ps --filter "name=frontend"`:
  ```
  CONTAINER ID   IMAGE                 COMMAND                  PORTS
  c6ec22649b1a   hybrid-lab-frontend   "/docker-entrypoint…"    0.0.0.0:5173->80/tcp, :::5173->80/tcp
  ```
  This explained why the old Vite/Docker frontend was accessible at `http://localhost:5173` and Vite development server had to fall back to `5174`.

### 2.2 Container Application Inspection
Inspecting the environment and code inside container `3b80f2c684ed`:
- `APP_NAME` in the container environment was `"Adaptive Hybrid Cloud Security Gateway"`.
- The container image did not include the production Vite build (`dist/`), causing its `main.py` fallback to return the JSON status dictionary.
- Every HTTP request to `http://localhost:8000` was captured by Docker before ever reaching the standalone executable.

### 2.3 Executable PyInstaller PYZ Archive Inspection
Using PyInstaller's `archive_viewer` on `AdaptiveSecurityGateway.exe`'s internal `PYZ.pyz`:
- Decompiled `backend.app.main` within the executable.
- Verified that `backend.app.main` contained:
  - `@app.get("/", include_in_schema=False)` -> `serve_root_dashboard()` returning `FileResponse(dist/index.html)`.
  - `@app.get("/{full_path:path}", include_in_schema=False)` -> `serve_spa_or_static()` returning static files or `dist/index.html`.
  - Zero occurrences of `{"app": "Adaptive Hybrid Cloud Security Gateway", ...}`.
- This proved beyond doubt that the running executable was not the source of the JSON.

---

## 3. Permanent Mitigation & Architectural Fixes

### 3.1 Docker Compose Port Re-Mapping
To permanently eliminate port collisions between the Docker simulated hybrid lab and the host standalone executable / Vite development environment:

1. **`deployment/hybrid-lab/compose.yaml`**:
   - Updated `gateway-api` port mapping:
     ```yaml
     ports:
       - "${GATEWAY_API_PORT:-8001}:8000"
     ```
   - Updated `frontend` port mapping:
     ```yaml
     ports:
       - "${FRONTEND_PORT:-5175}:80"
     ```
2. **`deployment/hybrid-lab/.env`**:
   - Added explicit variables:
     ```env
     GATEWAY_API_PORT=8001
     FRONTEND_PORT=5175
     ```
   - Updated `CORS_ORIGINS` to allow `http://localhost:5175` alongside existing origins.

### 3.2 Immediate Port Release
- Executed `docker stop hybrid-lab-gateway-api` -> Port 8000 released immediately on both `0.0.0.0` and `[::]`.
- Executed `docker stop hybrid-lab-frontend` -> Port 5173 released immediately on both `0.0.0.0` and `[::]`.
- Verified using socket test: Port 8000 is 100% available and bindable.

### 3.3 Backend Launcher Defensive Port Check
In `backend/launcher.py`, added a pre-flight socket availability check:
```python
def is_port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) != 0
```
If port 8000 is occupied by an external service (such as Docker or a rogue process), `launcher.py`:
1. Logs a prominent warning detailing the port collision.
2. Automatically shifts to an alternate safe port (`8080`).
3. Prevents silent Uvicorn crashes, guaranteeing the user is always informed of the actual serving URL.

---

## 4. Verification & Validation Matrix

| Test Case | Method | Expected Result | Observed Result | Status |
|:---|:---|:---|:---|:---:|
| Port 8000 Availability | Python `socket.bind(('127.0.0.1', 8000))` | Bind succeeds | Bind succeeds with zero error | **PASS** |
| Port 8000 IPv6 Check | Python `socket.bind(('::1', 8000))` | Bind succeeds | Bind succeeds with zero error | **PASS** |
| Container Collision Prevention | `compose.yaml` configuration audit | Ports 8001 & 5175 | Ports 8001 & 5175 configured | **PASS** |
| Root Serving In-Process Test | `TestClient(app).get("/")` | Returns `200 OK` with HTML | Returns `200 OK`, `text/html; charset=utf-8` | **PASS** |
| Swagger Docs Route Test | `TestClient(app).get("/docs")` | Returns `200 OK` Swagger UI | Returns `200 OK`, HTML docs | **PASS** |
| OpenAPI Schema Test | `TestClient(app).get("/openapi.json")` | Returns `200 OK` JSON | Returns `200 OK`, valid OpenAPI 3.1 | **PASS** |

---

## 5. Conclusion

The root JSON serving failure is completely diagnosed, proven by forensic artifact extraction, and permanently resolved. Port 8000 is fully freed for `AdaptiveSecurityGateway.exe`, and the Docker compose configuration has been re-anchored to non-conflicting ports (8001 and 5175).
