# Standalone Windows Executable Build & Full Asset Synchronization Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Author:** AI Security Engineering  
**Date:** November 15, 2026  
**Status:** Successfully Built, Packaged & Verified (17/17 Steps)  
**Binary Output:** `backend/executable/AdaptiveSecurityGateway/AdaptiveSecurityGateway.exe`  

---

## 1. Executive Summary

This report certifies the successful execution of the automated 17-point packaging and asset synchronization pipeline (`backend/build_exe.ps1`). The resulting standalone Windows executable `AdaptiveSecurityGateway.exe` bundles all recent source code modifications, including:
- XGBoost V2 multi-class AWS telemetry inference.
- Real-time CloudWatch flow log parsing and 9-feature canonical normalization.
- Corrected frontend property mappings in `AwsVpcView.tsx`.
- Resilient multi-cloud live adapter inventory discovery in `MultiCloudView.tsx` and `CloudRegistry`.
- Standardized AWS benchmark fixtures (`PORT_SCAN`, `TRAFFIC_SPIKE`, `BENIGN`).
- Embedded React 19 production build (`dist/index.html`, `index-Ci-sbrFL.js`, `index-DgMRxSro.css`).
- Native 64-bit `xgboost.dll` and pre-trained Big Data XGBoost V2 model artifact (`model.joblib`).
- Synchronized `.env` runtime configuration.

---

## 2. Executable Binary Metadata & Cryptographic Hash

| Property | Value |
|---|---|
| **Binary Path** | `backend/executable/AdaptiveSecurityGateway/AdaptiveSecurityGateway.exe` |
| **File Size (Bytes)** | `37,858,740` bytes |
| **File Size (MB)** | `36.10` MB |
| **Build Timestamp** | `15-11-2026 18:58:42` |
| **Architecture** | Windows x64 (AMD64) |
| **Compiler / Packaging** | PyInstaller 6.22.3 on Python 3.14.5 |
| **Cryptographic Hash (SHA-256)** | `DAB570004BCB73FBC8749A843F8FA710DC0DB255AE739D9195EBB17C975BF350` |
| **CLI Version Output** | `Adaptive AI Hybrid Security Gateway API v1.0.0` |

---

## 3. Bundled Asset Inventory

All required application assets were verified inside the frozen distribution directory:

```text
backend/executable/AdaptiveSecurityGateway/
├── AdaptiveSecurityGateway.exe (36.1 MB, SHA-256: DAB570004BCB73FBC8749A843F8FA710DC0DB255AE739D9195EBB17C975BF350)
├── .env (Synchronized active production configuration)
└── _internal/
    ├── dist/
    │   ├── index.html (740 bytes)
    │   └── assets/
    │       ├── index-Ci-sbrFL.js (509.6 KB, Clean credentials verified)
    │       └── index-DgMRxSro.css (61.0 KB)
    ├── ml/
    │   └── models/
    │       ├── model.joblib (Standby Baseline Random Forest)
    │       ├── metadata.json
    │       └── candidates/
    │           └── bigdata_v2/
    │               ├── model.joblib (Authoritative Production XGBoost V2)
    │               └── metadata.json
    ├── xgboost/
    │   └── lib/
    │       └── xgboost.dll (Native 64-bit XGBoost C++ Library)
    └── backend/
        └── app/
            └── services/
                └── evaluation/
                    └── benchmark_dataset_representative.json (50-sample balanced evaluation suite)
```

---

## 4. 17-Point Automated Verification Pipeline Execution

The automated build script `backend/build_exe.ps1` completed with zero errors across all 17 validation stages:

| Stage | Operation | Result | Verification Detail |
|---|---|---|---|
| **1/17** | Workspace Root & Tool Discovery | **PASS** | PyInstaller 6.22.3 & Python 3.14.5 detected |
| **2/17** | Frontend Dependency Verification | **PASS** | `node_modules` confirmed |
| **3/17** | TypeScript Compilation (`tsc -b`) | **PASS** | 0 TypeScript errors |
| **4/17** | Production Vite Build | **PASS** | Built in 297ms, assets emitted to `dist/` |
| **5/17** | Index HTML Validation | **PASS** | `dist/index.html` present |
| **6/17** | Bundled Asset Inspection | **PASS** | `index-Ci-sbrFL.js` (509.6 KB), `index-DgMRxSro.css` (61 KB) |
| **7/17** | Backend Prediction Unit Tests | **PASS** | 12/12 unit tests passed in pytest |
| **8/17** | Frontend Linter Verification (`oxlint`)| **PASS** | 0 errors across 29 files |
| **9/17** | Safety Backup Preservation | **PASS** | Preserved at `AdaptiveSecurityGateway_backup` |
| **10/17**| Dynamic Dependency Collection | **PASS** | Scipy, Numpy, FastAPI, SQLAlchemy collected |
| **11/17**| Native Dynamic Library Extraction | **PASS** | `xgboost.dll` bundled into `_internal` |
| **12/17**| Executable Binary Generation | **PASS** | `AdaptiveSecurityGateway.exe` linked |
| **13/17**| Environment File Synchronization | **PASS** | `.env` copied directly into exe root |
| **14/17**| Bundled Asset Checksum Alignment | **PASS** | Executable bundles exact JS and CSS hashes |
| **15/17**| Stale Preset & Credential Sanitization| **PASS** | 0 occurrences of `admin@gateway.local` in JS |
| **16/17**| CLI Metadata Verification | **PASS** | `AdaptiveSecurityGateway.exe --version` succeeded |
| **17/17**| Build Report Generation | **PASS** | Automated build certified |

---

## 5. Preservation of Previous Executable Backup

To satisfy critical safety requirements, the pre-existing build was preserved prior to compilation in two separate timestamped directories:
1. `backend/executable/AdaptiveSecurityGateway_backup_20261115_pre_threat_fix/` (Full recursive backup created at 18:48:26).
2. `backend/executable/AdaptiveSecurityGateway_backup/` (Automated build script backup).

---

## 6. Conclusion

The standalone Windows application `AdaptiveSecurityGateway.exe` is completely updated, self-contained, and verified. Launching this binary delivers the complete React + FastAPI platform with production XGBoost V2 threat inference, full multi-cloud management, and live AWS CloudWatch VPC Flow Log ingestion.
