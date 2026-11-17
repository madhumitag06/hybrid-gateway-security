# Phase 21.1 — Endpoint Authorization & RBAC Test Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `madhumitag06/hybrid-gateway-security`  
**Branch:** `main`  
**Baseline Commit:** `f472588bb35c45031a8a28dec2d19d626ea58daf`  
**Date:** November 16, 2026  
**Execution Environment:** In-Process FastAPI `TestClient` (Zero Localhost/Browser Network Requests)  

---

## 1. Test Suite Overview

Phase 21.1 expanded the gateway regression suite to rigorously validate all role boundaries, authentication guards, machine-to-machine service tokens, and negative authorization conditions.

- **Total Gateway Regression Tests:** **311 tests passed, 0 failed** in 42.40s.
- **Dedicated RBAC Authorization Suite:** `backend/tests/test_phase21_authorization_rbac.py` (7 test scenarios).
- **Execution Mode:** 100% in-process test execution via `fastapi.testclient.TestClient`. Zero network calls were issued to `127.0.0.1` or `localhost`, strictly satisfying the execution constraints.

---

## 2. Test Execution Matrix & Observed Results

### 2.1 Unauthenticated & Missing Token Verification (`test_unauthenticated_requests_return_401`)
Verifies that all protected sensitive endpoints reject unauthenticated calls with `401 Unauthorized`.

| Endpoint Tested | Method | Expected Status | Observed Status | Response Detail | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/v1/auth/me` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/auth/admin/users` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/enforcement/rules` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/enforcement/config` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/enforcement/config` | PUT | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/enforcement/rules/rule_123/revoke` | POST | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/analytics/summary` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/analytics/explain-flow` | POST | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/events` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/dashboard` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/system/profile` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/shadow/status` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/shadow/comparison` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/shadow/promote` | POST | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/shadow/rollback` | POST | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/adaptive/telemetry` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/adaptive/feedbacks` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/adaptive/feedback` | POST | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/adaptive/dataset/prepare` | POST | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/adaptive/train` | POST | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/adaptive/promote` | POST | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/cloud/providers` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/cloud/accounts` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/cloud/accounts` | POST | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/cloud/accounts/AWS/discover` | POST | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/cloud/resources` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/hybrid/topology` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/hybrid/lab-status` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/ingest/status` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/ingest/history` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/evaluation/suites` | GET | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |
| `/api/v1/evaluation/run` | POST | 401 | 401 | `Authentication required. Missing Bearer token.` | **PASS** |

---

### 2.2 Machine-to-Machine Service Authentication & Untrusted Network Guard
Tested using `remote_untrusted_client = TestClient(app, client=("198.51.100.25", 50000))` to simulate an untrusted remote IP.

| Scenario Description | Method & Endpoint | Credentials / Headers | Expected Status | Observed Status | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Remote untrusted IP without credentials | `POST /api/v1/predict` | None | 401 | 401 | **PASS** |
| Remote untrusted IP with invalid key | `POST /api/v1/predict` | `X-API-Key: invalid-key` | 401 | 401 | **PASS** |
| Remote untrusted IP with valid service key | `POST /api/v1/predict` | `X-API-Key: <service_key>` | 200 | 200 | **PASS** |
| Remote untrusted IP with valid service token | `POST /api/v1/predict` | `X-Service-Token: <service_key>` | 200 | 200 | **PASS** |
| Policy evaluation without credentials | `POST /api/v1/policies/evaluate` | None | 401 | 401 | **PASS** |
| Policy evaluation with valid service key | `POST /api/v1/policies/evaluate` | `X-API-Key: <service_key>` | 200 | 200 | **PASS** |

---

### 2.3 Standard `USER` Role Restriction Verification (`test_user_role_forbidden_from_admin_operator_and_analyst_endpoints`)
A provisioned user with role `USER` was issued a valid access token.

| Target Endpoint | Method | Required Role | Role Tested | Expected Status | Observed Status | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/v1/auth/me` | GET | Active User | USER | 200 | 200 | **PASS (Authorized)** |
| `/api/v1/analytics/summary` | GET | ANALYST | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/dashboard` | GET | ANALYST | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/events` | GET | ANALYST | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/cloud/providers` | GET | ANALYST | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/cloud/accounts` | GET | ANALYST | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/hybrid/topology` | GET | ANALYST | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/ingest/status` | GET | ANALYST | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/evaluation/suites` | GET | ANALYST | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/adaptive/feedback` | POST | ANALYST | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/enforcement/rules/{id}/revoke` | POST | OPERATOR | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/cloud/accounts/AWS/discover` | POST | OPERATOR | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/adaptive/dataset/prepare` | POST | OPERATOR | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/auth/admin/users` | GET | ADMIN | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/enforcement/config` | PUT | ADMIN | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/shadow/promote` | POST | ADMIN | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/adaptive/train` | POST | ADMIN | USER | 403 | 403 | **PASS (Forbidden)** |
| `/api/v1/cloud/accounts` | POST | ADMIN | USER | 403 | 403 | **PASS (Forbidden)** |

---

### 2.4 `ANALYST` and `AUDITOR` Role Verification (`test_analyst_and_auditor_roles_authorized_for_read_forbidden_from_mutations`)
Verified across both `ANALYST` and `AUDITOR` roles.

| Target Action / Endpoint | Method | Required Tier | Expected Status | Observed Status | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Read aggregated dashboard | `GET /api/v1/dashboard` | ANALYST | 200 | 200 | **PASS** |
| Read analytics summary | `GET /api/v1/analytics/summary` | ANALYST | 200 | 200 | **PASS** |
| Read security event list | `GET /api/v1/events` | ANALYST | 200 | 200 | **PASS** |
| Read cloud providers | `GET /api/v1/cloud/providers` | ANALYST | 200 | 200 | **PASS** |
| Revoke containment rule | `POST /api/v1/enforcement/rules/{id}/revoke` | OPERATOR | 403 | 403 | **PASS (Forbidden)** |
| Run evaluation benchmark | `POST /api/v1/evaluation/run` | OPERATOR | 403 | 403 | **PASS (Forbidden)** |
| Trigger AWS discovery | `POST /api/v1/cloud/accounts/AWS/discover` | OPERATOR | 403 | 403 | **PASS (Forbidden)** |
| List administrative users | `GET /api/v1/auth/admin/users` | ADMIN | 403 | 403 | **PASS (Forbidden)** |
| Mutate gateway config | `PUT /api/v1/enforcement/config` | ADMIN | 403 | 403 | **PASS (Forbidden)** |
| Promote model version | `POST /api/v1/shadow/promote` | ADMIN | 403 | 403 | **PASS (Forbidden)** |
| Trigger model retraining | `POST /api/v1/adaptive/train` | ADMIN | 403 | 403 | **PASS (Forbidden)** |

---

### 2.5 `OPERATOR` Role Operational Access (`test_operator_role_authorized_for_operations_but_forbidden_for_admin`)

| Action / Endpoint | Method | Required Role | Expected Status | Observed Status | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Prepare training dataset | `POST /api/v1/adaptive/dataset/prepare` | OPERATOR | 200 or 400 (validation) | 200/400 (NOT 403) | **PASS** |
| Revoke containment rule | `POST /api/v1/enforcement/rules/{id}/revoke` | OPERATOR | 404 (not found, NOT 403) | 404 | **PASS** |
| List administrative users | `GET /api/v1/auth/admin/users` | ADMIN | 403 | 403 | **PASS (Forbidden)** |
| Mutate gateway config | `PUT /api/v1/enforcement/config` | ADMIN | 403 | 403 | **PASS (Forbidden)** |
| Promote model version | `POST /api/v1/shadow/promote` | ADMIN | 403 | 403 | **PASS (Forbidden)** |
| Rollback model version | `POST /api/v1/shadow/rollback` | ADMIN | 403 | 403 | **PASS (Forbidden)** |
| Trigger candidate train | `POST /api/v1/adaptive/train` | ADMIN | 403 | 403 | **PASS (Forbidden)** |
| Add cloud account | `POST /api/v1/cloud/accounts` | ADMIN | 403 | 403 | **PASS (Forbidden)** |

---

### 2.6 `ADMIN` Role Full Access (`test_admin_role_authorized_for_all_endpoints`)
Authenticated as configured root administrator.

| Target Action / Endpoint | Method | Expected Status | Observed Status | Result |
| :--- | :--- | :--- | :--- | :--- |
| List administrative operators | `GET /api/v1/auth/admin/users` | 200 | 200 | **PASS** |
| Mutate enforcement config | `PUT /api/v1/enforcement/config` | 200 | 200 | **PASS** |
| Read aggregated dashboard | `GET /api/v1/dashboard` | 200 | 200 | **PASS** |

---

### 2.7 Token Tampering & Expiry Rejection (`test_invalid_and_tampered_token_rejection`)

| Attack Vector / Malformed Input | Expected Status | Observed Status | Result |
| :--- | :--- | :--- | :--- |
| Non-Bearer Authorization header (`Basic 123456`) | 401 | 401 | **PASS** |
| Malformed JWT string (`Bearer not.a.valid.jwt`) | 401 | 401 | **PASS** |
| Expired JWT access token (`expires_delta=-60s`) | 401 | 401 | **PASS** |
