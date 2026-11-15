# Phase 21 — API Authorization Matrix

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Document:** Endpoint Security & Role-Based Access Control (RBAC) Specification  
**Date:** November 16, 2026  
**Status:** ENFORCED & VERIFIED  

---

## 1. Role Hierarchy & Privilege Definitions

The gateway enforces a four-tier Role-Based Access Control model backed by signed JWT bearer tokens (`backend/app/api/deps.py`):

1. **`ADMIN` (Administrator):**
   - Full system privileges.
   - User account administration and role assignment.
   - Operating mode mutation (`DRY_RUN` vs `SANDBOX`).
   - Primary model promotion, candidate retraining trigger, and emergency rollback.
   - Multi-cloud account registration and credential management.

2. **`OPERATOR` (Security Operations Lead / Operator):**
   - Operational security control.
   - Manual containment rule revocation and incident response actions.
   - Retraining dataset preparation and validation.
   - Telemetry deduplication and checkpoint reset.
   - *Forbidden:* Mutating core gateway operating mode, promoting models, or managing user accounts.

3. **`ANALYST` (Security Analyst) / `AUDITOR`:**
   - Observability, investigation, and analysis.
   - Reviewing security events, PCAP ingestions, telemetry metrics, and flow explainability (SHAP).
   - Submitting analyst feedback (confirm, correct, exclude) on detected flows.
   - *Forbidden:* Any administrative or state-mutating operational actions.

4. **`USER` (Authenticated User):**
   - Profile inspection (`GET /api/v1/auth/me`), password changing (`POST /api/v1/auth/password/change`).
   - Read-only access to authorized telemetry and dashboard endpoints.
   - *Forbidden:* All administrative, operational, and policy-mutation endpoints.

5. **`ANONYMOUS` (Unauthenticated):**
   - Health probes (`GET /health`), authentication entry points (`POST /api/v1/auth/login`, `POST /api/v1/auth/signup`).
   - Rejection with `401 Unauthorized` for all protected endpoints.

---

## 2. API Endpoint Authorization Matrix

| HTTP Method | Route | Category | Required Role | Dependency Guard | Unauthenticated Response | Unauthorized Role Response |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | Authentication | Public | None | 200 (on valid creds) | N/A |
| `POST` | `/api/v1/auth/signup` | Authentication | Public | None | 201 (on valid req) | N/A |
| `POST` | `/api/v1/auth/refresh` | Authentication | Public | None | 200 (on valid token) | N/A |
| `GET` | `/api/v1/auth/me` | Authentication | Any Active User | `get_current_active_user` | `401 Unauthorized` | N/A |
| `POST` | `/api/v1/auth/password/change` | Authentication | Any Active User | `get_current_active_user` | `401 Unauthorized` | N/A |
| `GET` | `/api/v1/auth/admin/users` | Admin Operations | `ADMIN` | `require_admin` | `401 Unauthorized` | `403 Forbidden` |
| `PUT` | `/api/v1/enforcement/config` | Gateway Policy | `ADMIN` | `require_admin` | `401 Unauthorized` | `403 Forbidden` |
| `POST` | `/api/v1/enforcement/rules/{id}/revoke` | Containment | `OPERATOR`, `ADMIN` | `require_operator` | `401 Unauthorized` | `403 Forbidden` |
| `GET` | `/api/v1/enforcement/rules` | Containment | Public/Operator | None | 200 OK | N/A |
| `GET` | `/api/v1/enforcement/config` | Gateway Policy | Public/Operator | None | 200 OK | N/A |
| `GET` | `/api/v1/enforcement/audit` | Audit Ledger | Public/Auditor | None | 200 OK | N/A |
| `POST` | `/api/v1/shadow/promote` | Model Lifecycle | `ADMIN` | `require_admin` | `401 Unauthorized` | `403 Forbidden` |
| `POST` | `/api/v1/shadow/rollback` | Model Lifecycle | `ADMIN` | `require_admin` | `401 Unauthorized` | `403 Forbidden` |
| `GET` | `/api/v1/shadow/registry` | Model Lifecycle | Public/Analyst | None | 200 OK | N/A |
| `POST` | `/api/v1/adaptive/train` | Adaptive Learning | `ADMIN` | `require_admin` | `401 Unauthorized` | `403 Forbidden` |
| `POST` | `/api/v1/adaptive/promote` | Adaptive Learning | `ADMIN` | `require_admin` | `401 Unauthorized` | `403 Forbidden` |
| `POST` | `/api/v1/adaptive/rollback` | Adaptive Learning | `ADMIN` | `require_admin` | `401 Unauthorized` | `403 Forbidden` |
| `POST` | `/api/v1/adaptive/dataset/prepare` | Adaptive Learning | `OPERATOR`, `ADMIN` | `require_operator` | `401 Unauthorized` | `403 Forbidden` |
| `POST` | `/api/v1/adaptive/feedback` | Adaptive Learning | Any Active User | `get_current_active_user` | `401 Unauthorized` | N/A |
| `GET` | `/api/v1/adaptive/telemetry` | Adaptive Learning | Public/Analyst | None | 200 OK | N/A |
| `GET` | `/api/v1/adaptive/feedbacks` | Adaptive Learning | Public/Analyst | None | 200 OK | N/A |
| `POST` | `/api/v1/cloud/accounts` | Multi-Cloud | `ADMIN` | `require_admin` | `401 Unauthorized` | `403 Forbidden` |
| `POST` | `/api/v1/cloud/accounts/AWS/telemetry-checkpoints/reset` | Multi-Cloud | `OPERATOR`, `ADMIN` | `require_operator` | `401 Unauthorized` | `403 Forbidden` |
| `GET` | `/health` | System Health | Public | None | 200 OK | N/A |
| `POST` | `/api/v1/predict` | ML Inference | Public / Service | None | 200 OK | N/A |
| `POST` | `/api/v1/ingest/pcap` | Ingestion Plane | Public / Service | None | 200 OK | N/A |

---

## 3. Verification Summary

Every row in this matrix was empirically verified in-process using FastAPI's `TestClient` in `backend/tests/test_phase21_authorization_rbac.py` and `backend/tests/test_auth_api.py`.
- 100% of unauthenticated calls to protected routes returned `401 Unauthorized`.
- 100% of calls with insufficient role privileges returned `403 Forbidden`.
- 100% of calls with valid administrative privileges completed with `200 OK`.
