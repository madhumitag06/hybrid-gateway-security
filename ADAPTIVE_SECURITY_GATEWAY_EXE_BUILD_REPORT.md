# ADAPTIVE SECURITY GATEWAY STANDALONE EXECUTABLE BUILD REPORT
**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Artifact:** `AdaptiveSecurityGateway.exe`  
**Location:** `backend/executable/AdaptiveSecurityGateway/AdaptiveSecurityGateway.exe`  
**Build Date:** November 15, 2026  
**Compiler:** PyInstaller 6.16.0  
**Python Runtime:** Python 3.12.7 (64-bit Windows)  

---

## 1. Build Execution Summary

The standalone Windows application was rebuilt to package the verified FastAPI backend alongside the newly compiled Vite production React SPA distribution and authoritative ML assets.

```
Build Tool: PyInstaller 6.16.0
Spec File: backend/executable/AdaptiveSecurityGateway.spec
Target Mode: onedir (optimized for large ML runtimes)
Output Path: backend/executable/AdaptiveSecurityGateway/
Build Exit Code: 0 (SUCCESS)
```

---

## 2. Binary & Package Verification

### 2.1 File Metrics
- **Executable**: `AdaptiveSecurityGateway.exe`
- **File Size**: `37,856,341 bytes` (~36.1 MB)
- **SHA-256 Checksum**:  
  `0927B0CC9D961275A50C6744446CA324F81A8D4EBDFFB396FACB61C7E0D155CB`
- **Compilation Timestamp**: `2026-11-15 05:25:38 UTC+5:30`

### 2.2 CLI Execution Verification
The executable was verified in standard sandboxed execution:
```powershell
& 'backend\executable\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe' --version
```
- **Exit Code**: `0`
- **Output**: `Adaptive AI Hybrid Security Gateway API v1.0.0`

### 2.3 Bundled Components in `_internal`
All runtime assets were inspected and confirmed present:
1. **Frontend Distribution (`_internal/dist/`)**:
   - `index.html` (740 bytes)
   - `assets/index-BYKIx8vL.js` (521,174 bytes)
   - `assets/index-DgMRxSro.css` (62,500 bytes)
   - `favicon.svg`, `icons.svg`
2. **Native Binaries (`_internal/`)**:
   - `xgboost.dll` (56,915,456 bytes) at root and `xgboost/lib/`
   - OpenMP & VC++ runtime libraries (`vcomp140.dll`, etc.)
3. **Model Registry & Evaluation Data (`_internal/`)**:
   - `ml/models/production/` (Random Forest, 1,143,969 bytes)
   - `ml/models/candidates/bigdata_v2/` (XGBoost V2, 2,278,765 bytes)
   - `backend/app/services/evaluation/benchmark_dataset_representative.json` (336,825 bytes)
4. **Environment Configuration**:
   - `.env` verified at root of `AdaptiveSecurityGateway/` and within `_internal/`.

---

## 3. Safety Backup & Cleanup

- **Pre-Build Backup**: The prior executable distribution was preserved at:  
  `backend/executable/AdaptiveSecurityGateway_backup_20261115_pre_full_fix/`
- **Workpath Cleanup**: Temporary PyInstaller compilation directories in `build/` were removed post-build to conserve disk space, maintaining ~1.15 GB of free space on drive `C:`.

---

## 4. Operational Instructions

To launch the standalone application on Windows:
```powershell
cd c:\Users\LENOVO\Desktop\hybrid-gateway-security\backend\executable\AdaptiveSecurityGateway
.\AdaptiveSecurityGateway.exe
```
When launched:
1. FastAPI initializes Uvicorn on `http://localhost:8000`.
2. XGBoost native DLLs are loaded into process space.
3. Visiting `http://localhost:8000` serves the complete React dashboard via `dist/index.html`.
4. API discovery is available at `http://localhost:8000/api` and documentation at `http://localhost:8000/docs`.

---

## 5. Certification

The standalone executable package `AdaptiveSecurityGateway.exe` is built, fully synchronized with source code and frontend assets, and verified structurally sound.
