# Adaptive AI Hybrid Security Gateway — Standalone Backend Executable

This directory contains the standalone executable distribution configuration and runner for the FastAPI backend.

## 1. Quick Start (Run Standalone Backend)

From the project root:

```powershell
# Using the launcher wrapper:
.\backend\executable\AdaptiveSecurityGateway.cmd

# Or directly invoking the built binary:
.\backend\executable\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe
```

The executable will:
1. Automatically discover `.env` in the project root.
2. Initialize database connections to PostgreSQL (psycopg3).
3. Load the pre-trained Random Forest ML model, feature scaler, and SHAP background data.
4. Bind Uvicorn to `127.0.0.1:8000`.
5. Expose all REST endpoints (`/api/v1/...`), authentication APIs, PCAP ingestion, and WebSocket feeds.

---

## 2. Reproducible Build Process

To rebuild the standalone executable on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File backend/build_exe.ps1
```

Or using PyInstaller directly:

```powershell
.\ml\.venv\Scripts\pyinstaller.exe AdaptiveSecurityGateway.spec --noconfirm --distpath backend/executable
```

---

## 3. Options & Flags

```powershell
.\backend\executable\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe --help

options:
  -h, --help           Show help message and exit
  --host HOST          Host address to bind to (default: 127.0.0.1)
  --port PORT          Port number to bind to (default: 8000)
  --env-file ENV_FILE  Path to external .env configuration file
  --version            Show version number and exit
```
