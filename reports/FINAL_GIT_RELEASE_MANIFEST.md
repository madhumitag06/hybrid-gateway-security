# FINAL GIT RELEASE MANIFEST
## Adaptive AI-Powered Security Gateway for Hybrid Cloud

**Release Baseline:** Phase 22.8.5 / Phase 22.9  
**Execution Timestamp:** 2026-11-17T01:34:00+05:30  
**Repository Remote:** `https://github.com/madhumitag06/hybrid-gateway-security.git`  
**Branch:** `main`

---

## 1. Release Identification & Checksums

### Standalone Windows Executable
- **File Name:** `AdaptiveSecurityGateway.exe`
- **Relative Path:** `backend/executable/AdaptiveSecurityGateway/AdaptiveSecurityGateway.exe`
- **File Size:** `39,241,266 bytes` (37.42 MB)
- **SHA-256 Checksum:** `EDD8B360738A37C60E8CF084A3A5711D9542EFF52CD4B6C5EBEA48C7BD092279`
- **Build Timestamp:** `11/17/2026 01:34:04`
- **Bundled Frontend Assets:**
  - `dist/assets/index-BE1lsIoz.js` (546.73 kB)
  - `dist/assets/index-DgMRxSro.css` (62.50 kB)
- **Bundled ML Artifacts:**
  - Primary: `ml/models/candidates/bigdata_v2/` (9 features, XGBoost V2)
  - Standby: `ml/models/` (Random Forest Baseline)
  - Native DLL: `xgboost.dll`

---

## 2. Inventory of Tracked & Modified Core Files

### Backend & API Core
- `backend/app/api/deps.py`: Trusted management networks and RBAC dependencies.
- `backend/app/api/health.py`: Node readiness and Docker lab health checks.
- `backend/app/api/v1/adaptive.py`: Dynamic policy recommendation endpoints.
- `backend/app/api/v1/auth.py`: JWT issuance, SameSite refresh cookies, and session invalidation.
- `backend/app/api/v1/evaluation.py`: Model promotion, rollback, and benchmark evaluation.
- `backend/app/api/v1/hybrid.py`: Scenario execution and simulation status endpoints.
- `backend/app/api/v1/ingest.py`: PCAP and VPC Flow Log ingestion with M2M service token verification.
- `backend/app/config.py`: Configuration schemas, default trusted subnets (`10.30.10.0/24`).
- `backend/app/core/rate_limit.py`: Sliding-window IP rate limiter.
- `backend/app/services/hybrid_traffic_service.py`: Scenario-specific timeouts, active grace window, orphan sweeps.
- `backend/app/services/ml_service.py`: Production XGBoost V2 model registry with Random Forest standby.
- `backend/build_exe.ps1`: Automated 17-step build and packaging script.

### Frontend Application
- `src/App.tsx`: Central application layout, navigation routes, and active session context.
- `src/components/SimulationView.tsx`: Attack simulation cards, state transitions, and `LATE_COMPLETION` support.
- `src/components/EventsView.tsx`: Security events viewer and flow detail investigation modals.
- `src/components/TrafficView.tsx`: Real-time network throughput and telemetry counters.
- `src/services/auth.ts`: Authentication API client with refresh cookie handling.
- `src/services/hybrid.ts`: Scenario trigger and status polling client.

### Hybrid Lab & Infrastructure
- `deployment/hybrid-lab/compose.yaml`: Complete 13-container microservice definition.
- `deployment/hybrid-lab/gateway/Dockerfile`: Non-root gateway image with Python 3.12.
- `deployment/hybrid-lab/telemetry/Dockerfile`: Telemetry sensor container definition.
- `deployment/hybrid-lab/telemetry/sensor_service.py`: Ingestion client sending `X-Service-Token`.
- `deployment/hybrid-lab/telemetry/ingestion_ledger.py`: SHA-256 persistent PCAP deduplication ledger.
- `deployment/hybrid-lab/traffic-generator/Dockerfile`: Traffic generator image definition.
- `deployment/hybrid-lab/traffic-generator/trigger_daemon.py`: File-based IPC trigger daemon.

### Test Suites
- `backend/tests/conftest.py`: Test fixtures and strict authentication controls.
- `backend/tests/test_phase21_authorization_rbac.py`: RBAC route protection test suite.
- `backend/tests/test_phase22_3_db_migration.py`: Database schema upgrade/downgrade validation.
- `backend/tests/test_phase22_3_network_authorization.py`: Network origin verification.
- `backend/tests/test_phase22_4_hardening.py`: Application security hardening tests.
- `backend/tests/test_phase22_7_runtime_integrity.py`: XGBoost V2 registry integrity.
- `backend/tests/test_phase22_8_3_simulation_rendering.py`: Scenario rendering and timeout tests.
- `backend/tests/test_phase22_8_telemetry_idempotency.py`: SHA-256 ingestion deduplication tests.
- `backend/tests/test_phase22_remediation.py`: SEC-01 through SEC-14 verification tests.
- `backend/tests/test_phase22_service_key_hardening.py`: Machine-to-machine authentication tests.

---

## 3. Exclusion & Secret Protection Verification

Verification confirms that no secrets or unwanted files are staged:
- `.env` files: **ZERO .env files staged or committed** (strictly gitignored).
- `*.pcap`: Excluded from Git.
- `*.db`: SQLite/PostgreSQL local databases excluded.
- `backend/executable/AdaptiveSecurityGateway/`: Excluded from Git.
- Template `.env.example`: Synchronized with sanitized placeholder values.
