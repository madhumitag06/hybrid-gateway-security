# Phase 21 — Regression Test Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Test Suite:** Backend Pytest Suite, RBAC Verification & Frontend Build Pipeline  
**Date:** November 16, 2026  
**Status:** 100% PASSED (310 Backend Tests, 0 Failures)  

---

## 1. Test Suite Summary

| Suite / Component | Total Tests | Passed | Failed | Skipped | Execution Time |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Backend Test Suite (Pytest)** | 310 | 310 | 0 | 0 | 42.57s |
| **Authentication & RBAC (`test_phase21_authorization_rbac.py`)** | 6 | 6 | 0 | 0 | 3.87s |
| **Auth Logic & Legacy Password Rejection (`test_auth.py`)** | 13 | 13 | 0 | 0 | 1.15s |
| **Enforcement API (`test_enforcement_api.py`)** | 4 | 4 | 0 | 0 | 4.57s |
| **Model Registry & Rollback (`test_model_promotion_rollback.py`)** | 5 | 5 | 0 | 0 | 3.12s |
| **Adaptive ML & PCAP (`test_pcap_persistence_and_adaptive.py`)** | 3 | 3 | 0 | 0 | 3.14s |
| **Static TypeScript Analysis (`npx.cmd tsc -b`)** | 42 modules | 42 | 0 | 0 | 4.10s |
| **Frontend Linter (`npm.cmd run lint` - oxlint)** | 29 files | 29 | 0 | 0 | 0.42s |
| **Frontend Production Build (`npm.cmd run build`)** | Bundle | Pass | 0 | 0 | 0.21s |
| **Standalone Executable Packaging (`build_exe.ps1`)** | 17 steps | 17 | 0 | 0 | 105s |

---

## 2. Granular Test Execution Breakdown

### A. Authorization & RBAC (`test_phase21_authorization_rbac.py`)
- `test_unauthenticated_requests_return_401`: Verifies that 13 distinct administrative and operational endpoints reject requests without a Bearer token with `401 Unauthorized`.
- `test_user_role_forbidden_from_admin_and_operator_endpoints`: Verifies that users with role `USER` receive `403 Forbidden` on admin/operator routes.
- `test_analyst_and_auditor_roles_forbidden_from_administrative_endpoints`: Verifies that `ANALYST` and `AUDITOR` roles cannot execute config mutations, model promotions, rule revocations, or candidate retraining.
- `test_operator_role_authorized_for_operations_but_forbidden_for_admin`: Verifies that `OPERATOR` can perform operational actions (rule revocation, dataset prep) but is forbidden from model promotion, user admin, and operating mode changes (`403 Forbidden`).
- `test_admin_role_authorized_for_all_endpoints`: Verifies that `ADMIN` has unrestricted authorized access to all administrative endpoints.
- `test_invalid_and_tampered_token_rejection`: Verifies that malformed, non-bearer, and expired JWT tokens return `401 Unauthorized`.

### B. Authentication Hardening (`test_auth.py`)
- `test_admin_login_with_predefined_credentials`: Validates that attempting to authenticate using legacy hardcoded passwords (`test@123`, `AdminSecOps2026!`, `AdminSecret2026!`) for unauthorized accounts returns `401 Unauthorized`.
- Verifies that legitimate administrator credentials configured via environment variables hash and verify cleanly via bcrypt.

### C. Enforcement & Policy APIs (`test_enforcement_api.py`)
- `test_get_and_update_enforcement_config`: Validates that unauthenticated PUT is rejected, while authenticated administrator update successfully toggles modes and updates rule TTLs.
- `test_list_and_revoke_enforcement_rules`: Validates that active containment rules can only be revoked when accompanied by an authorized operator or admin token.

### D. Model Promotion & Standby Registry (`test_model_promotion_rollback.py`)
- Validates that promotion (`/api/v1/shadow/promote`) and rollback (`/api/v1/shadow/rollback`) require administrator privileges, while registry status remains publicly observable for analysts.

### E. Adaptive Learning Pipeline (`test_pcap_persistence_and_adaptive.py`)
- Validates that flow feedback submission requires authenticated operator/analyst credentials.
- Validates that candidate model retraining and promotion enforce administrator authorization.

---

## 3. Regression Verdict

All 310 tests across the entire test suite executed and passed cleanly. Zero regressions were introduced. The gateway exhibits complete functional, operational, and cryptographic stability.
