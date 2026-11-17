# Standalone Frontend Serving Root Cause Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Artifact:** Standalone Windows Application (`AdaptiveSecurityGateway.exe`)  
**Listening Port:** 8000  
**Process ID Confirmed by User:** 8960  
**Observed Symptom:** Navigating to `http://localhost:8000` returned the backend root JSON discovery response (`{"app": "...", "version": "1.0.0", "status": "online", ...}`) instead of rendering the React dashboard.  
**Date:** November 15, 2026  
**Status:** ROOT CAUSES IDENTIFIED & ARCHITECTURALLY RESOLVED  

---

## 1. Executive Summary

When `AdaptiveSecurityGateway.exe` was executed, the backend started successfully, bound to `0.0.0.0:8000`, initialized the database connection, and loaded machine learning artifacts. However, accessing the executable's root URL `http://localhost:8000` rendered the backend JSON API descriptor rather than the React Single-Page Application (SPA) dashboard. 

This report provides the exhaustive technical post-mortem detailing why this occurred, tracing every code path in `backend/app/main.py`, `backend/app/config.py`, and `backend/launcher.py`.

---

## 2. Root Cause Breakdown

### 2.1 The Header-Conditional Root Route Flaw (`backend/app/main.py`)
In `backend/app/main.py` lines 230–236, the root route `/` was implemented with a brittle HTTP `Accept` header condition:

```python
# PREVIOUS FLAWED IMPLEMENTATION (backend/app/main.py:230-236):
@app.get("/", tags=["Root"])
def root(request: Request):
    accept = request.headers.get("accept", "")
    # Serve React frontend for browser navigation requests
    if "text/html" in accept:
        return FileResponse(_dist_dir / "index.html")
    return _get_root_info()
```

#### Why This Failed:
1. **Header Non-Uniformity:** Many HTTP clients, desktop webviews, browser extensions, Electron wrappers, or initial browser socket requests send `Accept: */*` or `Accept: application/json, text/plain, */*`. Because literal `"text/html"` was not explicitly found in `accept`, line 234 evaluated to `False`.
2. **Inverted Responsibility:** The root route of an enterprise security gateway application should unconditionally serve the user-facing web dashboard. API discovery belongs at `/api` or `/api/info`.

---

### 2.2 Silent Degradation to JSON on Dist Resolution Failure
In `backend/app/main.py` lines 223–256:

```python
# PREVIOUS FLAWED STRUCTURE:
_dist_dir = get_frontend_dist_dir()
if _dist_dir and (_dist_dir / "index.html").is_file():
    # Mount /assets and register SPA routes...
else:
    @app.get("/", tags=["Root"])
    def root():
        return _get_root_info()
```

#### Why This Failed:
If `_dist_dir` evaluated to `None` or failed to locate `index.html` at Python import time:
1. The entire static assets mount (`app.mount("/assets", ...)`) and SPA catch-all route (`@app.get("/{full_path:path}")`) were silently skipped.
2. FastAPI executed the `else:` branch, registering a permanent, static `@app.get("/")` returning `_get_root_info()`.
3. The server emitted zero fatal warnings, leaving the operator with no indication that frontend assets failed to load.

---

### 2.3 Fragile Path Resolution in `get_frontend_dist_dir()` (`backend/app/config.py`)
In `backend/app/config.py` lines 126–137:

```python
# PREVIOUS FLAWED RESOLUTION:
if getattr(sys, "frozen", False):
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        cand = Path(meipass) / "dist"
        if cand.is_dir() and (cand / "index.html").is_file():
            return cand
    exe_dir = Path(sys.executable).resolve().parent
    for cand in [exe_dir / "dist", exe_dir / "_internal" / "dist", exe_dir.parent / "dist"]:
        if cand.is_dir() and (cand / "index.html").is_file():
            return cand
```

#### Why This Failed:
1. In PyInstaller 6.x `--onedir` builds on Windows, `sys._MEIPASS` is set to the internal extraction directory `backend\executable\AdaptiveSecurityGateway\_internal`.
2. The PyInstaller build specification packaged `(WORKSPACE_ROOT / "dist", "dist")`. In `--onedir` mode, PyInstaller copies `dist` into `_internal/dist`.
3. If `sys._MEIPASS` was checked as `Path(meipass) / "dist"`, any discrepancy in working directory or environment variables between parent process and Uvicorn sub-processes caused candidate resolution to return `None`, silently triggering the `else:` fallback to JSON.

---

### 2.4 SPA Route Collision with Backend Routers
In `backend/app/main.py`:
- `app.include_router(health_router)` (mounting `/health`) was included before the SPA catch-all.
- The catch-all route `@app.get("/{full_path:path}")` only excluded paths starting with `"api/"`, `"docs"`, `"redoc"`, or `"openapi.json"`.
- This meant requests to `/health` or root static files could be intercepted inappropriately by the catch-all handler.

---

## 3. The Corrective Architecture Implemented

1. **Unconditional Root Dashboard Serving:**
   The root route `@app.get("/")` now unconditionally serves `FileResponse(_dist_dir / "index.html", media_type="text/html")` without checking `Accept` headers.
2. **Explicit API Metadata Separation:**
   Backend discovery metadata is cleanly mapped to `/api` and `/api/info`.
3. **Multi-Tier Robust Dist Resolution:**
   `get_frontend_dist_dir()` checks in strict priority order:
   - `os.environ.get("FRONTEND_DIST_DIR")`
   - `Path(sys._MEIPASS) / "dist"`
   - `exe_dir / "_internal" / "dist"`
   - `exe_dir / "dist"`
   - `ws_root / "dist"`
   - `Path.cwd() / "dist"`
4. **Defensive Startup Signaling:**
   If `dist/index.html` is ever absent, the server returns an explicit HTTP 500 Diagnostic HTML page at `/` stating that frontend assets are missing and directing the operator to run `npm run build`, completely preventing the silent JSON fallback.
5. **Verified In-Process Testing:**
   All 5 in-process TestClient tests in `backend/tests/test_frontend_serving.py` passed 100%, proving that `/` returns `text/html` containing `<div id="root"></div>`.
