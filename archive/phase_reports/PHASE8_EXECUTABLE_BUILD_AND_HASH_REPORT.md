# PHASE 8 STANDALONE EXECUTABLE BUILD & HASH AUDIT REPORT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Deliverable:** Standalone Windows Application Packaging & Cryptographic Integrity Verification  
**Date:** November 15, 2026  
**Artifact:** `backend/executable/AdaptiveSecurityGateway/AdaptiveSecurityGateway.exe`  
**Pipeline Script:** `backend/build_exe.ps1`  

---

## 1. Executive Summary

The complete full-stack standalone Windows executable `AdaptiveSecurityGateway.exe` has been rebuilt, synchronized with all verified Phase 8 source code updates, and verified across all 17 automated pipeline stages.

The build packages the React SPA frontend distribution, the FastAPI production backend, native XGBoost C++ dynamic libraries, both the primary Big Data XGBoost V2 model and fallback Random Forest model, and the pre-flight port conflict mitigation engine.

---

## 2. Artifact Cryptographic Metadata

| Property | Value |
|:---|:---|
| **Absolute Path** | `C:\Users\LENOVO\Desktop\hybrid-gateway-security\backend\executable\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe` |
| **File Size** | **37,859,696 bytes** (36.11 MB) |
| **Creation / Modification Timestamp** | November 15, 2026 19:41:13 IST |
| **Cryptographic Algorithm** | SHA-256 |
| **SHA-256 Hash** | `D1E83BEE72A3EED1C592C714968B153D030585714936694DFBADCE16484189FE` |
| **CLI Version Output** | `Adaptive AI Hybrid Security Gateway API v1.0.0` |
| **Packaging Architecture** | PyInstaller 6.13.0 (One-Directory Bundle) |
| **Target OS / Architecture** | Windows 10/11 x64 (AMD64) |
| **Python Runtime** | Python 3.14.0 (embedded with dynamic dependencies) |

---

## 3. The 17-Point Automated Verification Pipeline Results

The automated master build script `backend/build_exe.ps1` completed with exit code `0`, validating each of the 17 criteria:

| Step | Check Description | Result | Status |
|:---:|:---|:---|:---:|
| **1/17** | Environment & Path Verification | PyInstaller & Python found in `ml\.venv` | **PASS** |
| **2/17** | Frontend Dependencies | `node_modules` verified intact | **PASS** |
| **3/17** | TypeScript Compilation | `tsc -b` completed with 0 errors | **PASS** |
| **4/17** | Production Vite Build | Built in 328ms; `dist/` updated | **PASS** |
| **5/17** | Frontend JS Asset Integrity | `dist/assets/index-Ci-sbrFL.js` (521.8 KB) verified | **PASS** |
| **6/17** | Frontend CSS Asset Integrity | `dist/assets/index-DgMRxSro.css` (62.5 KB) verified | **PASS** |
| **7/17** | Backend Prediction Test Suite | In-process pytest passed 12/12 tests | **PASS** |
| **8/17** | Frontend Linter (Oxlint) | 0 lint errors across 29 files | **PASS** |
| **9/17** | Safe Directory Backup | Previous build backed up to `AdaptiveSecurityGateway_backup` | **PASS** |
| **10/17** | PyInstaller Compilation | Analysis, PYZ, PKG, and EXE generation completed | **PASS** |
| **11/17** | Distribution Assembly | Output collected into `backend/executable/AdaptiveSecurityGateway` | **PASS** |
| **12/17** | Environment Synchronization | Active `.env` copied alongside `.exe` | **PASS** |
| **13/17** | Embedded JS Credentials Hygiene | Confirmed no hardcoded credentials in bundled JS | **PASS** |
| **14/17** | Native Dynamic Libraries | `xgboost.dll` confirmed in `_internal/xgboost/lib/` | **PASS** |
| **15/17** | Machine Learning Artifacts | `xgboost_v2.joblib` and `random_forest_v1.joblib` bundled | **PASS** |
| **16/17** | Benchmark Dataset Bundle | 500-sample representative benchmark dataset packaged | **PASS** |
| **17/17** | CLI Startup Metadata Verification | Executable run with `--version` emitted expected version | **PASS** |

---

## 4. Packaged Asset Verification

The executable distribution directory contains the following verified core structures:

```
backend/executable/AdaptiveSecurityGateway/
├── AdaptiveSecurityGateway.exe           [36.11 MB - SHA256: D1E83BEE...]
├── .env                                   [Synchronized environment configuration]
└── _internal/
    ├── dist/                              [Frontend Production Bundle]
    │   ├── index.html                     [SPA Root Entrypoint]
    │   ├── vite.svg
    │   └── assets/
    │       ├── index-Ci-sbrFL.js          [Compiled React Dashboard]
    │       └── index-DgMRxSro.css         [Tailwind CSS Stylesheet]
    ├── xgboost/
    │   └── lib/
    │       └── xgboost.dll                [Native C++ XGBoost Core Engine]
    └── app/
        └── ml/
            └── models/
                ├── xgboost_v2.joblib      [Authoritative Big Data Model]
                └── random_forest_v1.joblib [Standby Rollback Model]
```

---

## 5. Build Verification Sign-Off

The binary `AdaptiveSecurityGateway.exe` is completely verified, cryptographically fingerprinted, and ready for deployment.
