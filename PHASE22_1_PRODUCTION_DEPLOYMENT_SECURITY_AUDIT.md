# PHASE 22.1 — PRODUCTION DEPLOYMENT & INFRASTRUCTURE SECURITY AUDIT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `madhumitag06/hybrid-gateway-security`  
**Current Branch:** `main`  
**Baseline Commit:** `f472588bb35c45031a8a28dec2d19d626ea58daf`  
**Audit Execution Mode:** STRICT READ-ONLY FORENSIC AUDIT (Zero Source Changes, Zero Commits/Pushes)  
**Date:** November 16, 2026  
**Auditor:** Antigravity Autonomous Security Engineering Agent  

---

## 1. Executive Summary

Phase 22.1 conducted a comprehensive, evidence-based production deployment and infrastructure security audit across all supported deployment pathways: Docker Compose (virtual hybrid lab), standalone Windows executable, bare-metal FastAPI startup, GitHub Actions workflows, and Terraform blueprints.

### Summary of Audit Posture
While Phase 22.0 successfully resolved machine-to-machine service key defaults and constant-time verification, this infrastructure-wide audit identified **two CRITICAL production blockers** in authentication workflows, **two HIGH-severity risks** in configuration and artifact packaging, and several MEDIUM/LOW findings across deployment workflows and browser headers:

1. **CRITICAL Blocker (Auth Bypass Backdoor):** A development/testing mock hook (`id_token_str.startswith("mock_google_")`) remains active in `backend/app/services/auth_service.py` on the public endpoint `POST /api/v1/auth/google/token`. Any unauthenticated remote caller can forge an arbitrary email (including the administrator's email) to completely bypass authentication and obtain a full root `ADMIN` JWT token without contacting Google.
2. **CRITICAL Blocker (Privilege Escalation via Self-Registration):** The public endpoint `POST /api/v1/auth/signup` permits callers to specify `role: "OPERATOR"`. An unauthenticated caller can self-provision an active, verified account with elevated `OPERATOR` privileges, granting the ability to revoke firewall containment rules and modify enforcement policies.
3. **HIGH Risk (Insecure Production Fallbacks for JWT & Admin Passwords):** While `GATEWAY_SERVICE_KEY` enforces fail-closed validation in `Settings`, `AUTH_JWT_SECRET`, `SECRET_KEY`, and `ADMIN_PASSWORD` continue to fall back to hardcoded development defaults if not explicitly set in the environment when `APP_ENV=production`.
4. **HIGH Risk (Packaging Bundles Developer Secrets):** `AdaptiveSecurityGateway.spec` explicitly bundles host `.env` files into `_internal\.env`, and `backend/build_exe.ps1` copies `.env` into the executable distribution directory. Distributing or publishing the standalone package discloses developer credentials, database connection strings, and API keys.

---

## 2. Exact Files and Configurations Inspected

### Application Code & Configuration
- `backend/app/config.py`: Configuration loading, `Settings` validation, path resolution, environment detection.
- `backend/app/main.py`: Lifespan startup, middleware registration, CORS, security headers, SPA static routing.
- `backend/app/api/deps.py`: User retrieval, RBAC enforcement (`require_admin`, `require_operator`, `require_analyst`), service authentication (`require_service_or_trusted_network`).
- `backend/app/core/security.py`: Password hashing (bcrypt), token creation (JWT), expiration, token decoding.
- `backend/app/services/auth_service.py`: User signup, login, refresh rotation, logout, password change, Google OAuth handling, admin bootstrap.
- `backend/app/api/v1/auth.py`: Authentication API route definitions and public exposure.
- `backend/app/api/v1/ingest.py`: File upload limits, size checks, extension validation, temporary file cleanup.
- `backend/app/db/session.py`: Engine pooling, session lifecycle, transaction commits/rollbacks, `init_db()`.
- `backend/app/services/policy_engine.py`: CIDR matching and allowlist evaluation (`is_ip_allowlisted`).
- `src/services/auth.ts`: Frontend token persistence (`localStorage`), token refresh interceptor, authentication headers.

### Deployment Manifests & Blueprints
- `deployment/hybrid-lab/compose.yaml`: Multi-container Docker lab architecture, network boundaries, privilege flags, volume mounts.
- `deployment/hybrid-lab/gateway/Dockerfile`: Container base image, build steps, user execution context, exposed ports.
- `deployment/hybrid-lab/gateway/entrypoint.sh`: Container entrypoint, Alembic migration execution, uvicorn startup.
- `deployment/hybrid-lab/frontend/Dockerfile`: Frontend web server container build.
- `deployment/hybrid-lab/frontend/nginx.conf`: Reverse proxy configuration, timeouts, buffer sizes, forwarded headers.
- `deployment/hybrid-lab/.env.example`: Virtual lab environment template.
- `.env.example`: Root project configuration template.
- `infrastructure/environments/production/main.tf`: Terraform production root module.
- `infrastructure/modules/security-gateway/main.tf`: Container manifest blueprint.

### CI/CD Workflows & Packaging Specifications
- `.github/workflows/ci.yml`: Continuous integration test jobs and test file selection.
- `.github/workflows/docker-build.yml`: Container image build workflow.
- `.github/workflows/windows-exe-build.yml`: Windows runner PyInstaller build script.
- `.github/workflows/release.yml`: GitHub release draft creation.
- `.github/workflows/security-scan.yml`: Bandit AST analysis and pip-audit execution.
- `AdaptiveSecurityGateway.spec`: PyInstaller build specification, collected binaries, bundled data files.
- `backend/build_exe.ps1`: Automated 17-step build and packaging pipeline.
- `.gitignore`: Repository secret and artifact exclusion rules.
- `package.json` & `package-lock.json`: Frontend dependencies and audit definitions.
- `backend/requirements.txt` & `ml/requirements.txt`: Python package dependency specifications.

---

## 3. Deployment-Path Comparison

| Evaluation Dimension | Docker Compose (Hybrid Lab) | Standalone Windows EXE | Bare-Metal / Direct FastAPI | Terraform Cloud Blueprint |
| :--- | :--- | :--- | :--- | :--- |
| **Execution User** | `root` (UID 0) | Current Windows User | Invoking OS User | Target Container Runtime (ECS/Cloud Run) |
| **Startup Migration** | Automatic (`entrypoint.sh` runs `alembic upgrade head`) | Manual / Bypass (`init_db()` calls `create_all`) | Manual (`init_db()` calls `create_all`) | Not defined in manifest |
| **Config Source** | `compose.yaml` + `deployment/hybrid-lab/.env` | Bundled `_internal\.env` or alongside `.exe` | Shell Environment or `.env` in root | Container task environment variables |
| **Fail-Closed Guard** | Depends on `ENV` variable (defaults to non-prod) | Validates at startup based on `.env` | Enforced if `APP_ENV=production` | Enforced if `APP_ENV=production` |
| **Network Exposure** | Host port `8001:8000`, `5175:80` | `127.0.0.1:8000` (configurable) | `127.0.0.1:8000` | Cloud Load Balancer / Ingress |
| **Production Ready?** | **NO** (Lab configuration only) | **NO** (Contains bundled `.env`) | **NO** (Requires explicit environment) | **NO** (Blueprint lacks secret definitions) |

---

## 4. Authentication and JWT Audit

### 4.1 JWT Architecture & Lifecycle
- **Algorithm:** `HS256` (HMAC with SHA-256). Verified strictly via `algorithms=[settings.auth_jwt_algorithm]`, preventing `alg: "none"` confusion attacks.
- **Access Token Expiration:** Default 60 minutes (`auth_access_token_expire_minutes: 60`).
- **Refresh Token Expiration:** Default 7 days (`auth_refresh_token_expire_days: 7`).
- **Rotation & Revocation:** Every token refresh revokes the existing refresh token in `RefreshTokenRepository` and issues a fresh pair (single-use rotation). Logout invalidates the active refresh token. Password change revokes all active refresh tokens for the user.
- **Cryptographic Hashing:** Passwords hashed with bcrypt (`rounds=12`, random salt per password). Verification uses `bcrypt.checkpw` in constant time.

### 4.2 Critical Authentication Vulnerabilities Identified
1. **Mock Google Token Bypass (`AuthService.handle_google_id_token`):**
   ```python
   # Lines 319-327 of backend/app/services/auth_service.py
   if id_token_str.startswith("mock_google_"):
       parts = id_token_str.split(":")
       email_part = parts[1] if len(parts) > 1 else "google_test@example.com"
       name_part = parts[2] if len(parts) > 2 else "Google Operator"
       sub_part = parts[3] if len(parts) > 3 else "google-sub-123456"
       return cls._process_google_user_info(...)
   ```
   This development hook is exposed on the unauthenticated public route `POST /api/v1/auth/google/token`. An attacker can submit any email address; if the email matches an existing administrator account, `_process_google_user_info` returns a valid JWT with `role="ADMIN"`.
2. **Unauthenticated Privilege Escalation via Signup (`AuthService.signup`):**
   ```python
   # Line 81 of backend/app/services/auth_service.py
   effective_role = req.role if req.role in ("OPERATOR", "ANALYST", "AUDITOR", "USER") else "ANALYST"
   ```
   The public registration endpoint `POST /api/v1/auth/signup` allows callers to self-assign the `OPERATOR` role, granting unauthorized containment rule revocation and policy modification capabilities.
3. **Frontend Token Storage:**
   Tokens are stored in `localStorage` (`hgs_auth_tokens`), rendering refresh tokens vulnerable to exfiltration if a script injection (XSS) flaw is introduced.

---

## 5. HTTP and Browser Security Audit

### 5.1 CORS Configuration
- `CORSMiddleware` uses `allow_origins=settings.cors_origins` and `allow_credentials=True`.
- In `config.py`, default origins include `http://localhost:5173`, `http://localhost:3000`, etc.
- In production, explicit production domains must be configured; wildcard `*` cannot be used with `allow_credentials=True`.

### 5.2 HTTP Security Headers
- **Injected Headers (`backend/app/main.py`):**
  - `X-Content-Type-Options: nosniff` (Active)
  - `X-Frame-Options: DENY` (Active)
  - `X-XSS-Protection: 1; mode=block` (Deprecated, MDN advises replacement with CSP)
  - `Referrer-Policy: strict-origin-when-cross-origin` (Active)
  - `Permissions-Policy: geolocation=(), camera=(), microphone=()` (Active)
- **Missing Headers:**
  - `Content-Security-Policy` (CSP) is completely absent from backend responses.
  - `Strict-Transport-Security` (HSTS) is not injected by FastAPI (relies entirely on external TLS terminators).

### 5.3 CSRF & Upload Controls
- **CSRF:** Authenticated state relies exclusively on the `Authorization: Bearer <token>` header, neutralizing browser ambient cookie CSRF attacks.
- **Upload Safety:** `POST /api/v1/ingest/pcap` enforces a 15 MB limit (`MAX_UPLOAD_SIZE_BYTES`), validates file extensions (`.pcap`, `.pcapng`, `.cap`), uses sanitized basenames, writes to a temporary directory created via `tempfile.mkdtemp`, and guarantees directory deletion in a `finally` block.

---

## 6. Database Audit

### 6.1 Connection Pooling & Engine Configuration
- SQLAlchemy 2.0 engine configured with connection pooling (`pool_size=10`, `max_overflow=20`, `pool_pre_ping=True`).
- `get_db()` dependency ensures per-request session lifecycle, automatically committing on success, rolling back on unhandled exceptions, and closing sessions in `finally`.

### 6.2 Migration Ownership & Schema Divergence Risk
- **Alembic Ownership:** Revision `004_consolidated_enterprise_schema.py` persists table ownership in `_alembic_004_created_tables`. Re-verified to be process-persistent across independent OS processes.
- **Dual Initialization Hazard:** `backend/app/main.py` calls `init_db()` during startup lifespan, which executes `Base.metadata.create_all(bind=engine)`. If the application starts before Alembic migrations are executed, tables are created without Alembic version stamping. Any subsequent `alembic upgrade head` fails with table collision errors on revisions 001, 002, and 003.

---

## 7. Docker and Network Isolation Audit

### 7.1 Container Security & Privileges
- **User Execution:** `deployment/hybrid-lab/gateway/Dockerfile` lacks a `USER` directive and runs as root (`UID 0`).
- **Build Tools:** The runtime image contains `gcc` and `libpq-dev`. A multi-stage build should be employed to discard build utilities from the final image.
- **Network Boundaries:**
  - `onprem_net` (`10.10.10.0/24`): `internal: true`.
  - `cloud_vpc_net` (`10.20.10.0/24`): `internal: true`.
  - `mgmt_net` (`10.30.10.0/24`): Standard bridge. `postgres` has no published ports to the host.

### 7.2 Conflation of Management Allowlist with API Authentication
- In `backend/app/api/deps.py`, `require_service_or_trusted_network` checks `PolicyEngine.is_ip_allowlisted(client_ip)`.
- `MANAGEMENT_ALLOWLIST` was designed to exempt critical infrastructure (DNS, routers) from firewall blocking. Using this same list to bypass API authentication allows any caller whose IP matches the allowlist to access protected APIs without credentials.

---

## 8. Standalone EXE Integrity & Checksum Verification

### 8.1 Independent Cryptographic Verification
Both executable files were independently hashed using PowerShell `Get-FileHash -Algorithm SHA256`:

| Target Executable | File Size | Independently Verified SHA-256 Digest | Match with Phase 22.0 Report |
| :--- | :--- | :--- | :--- |
| **Active Executable** (`backend\executable\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe`) | 37,886,391 bytes | `82DDB68A31481E3824B1CA6959BC97F53378EA63BAA4AC1ABE87EE673BEE9F8D` | **EXACT MATCH (VERIFIED)** |
| **Rollback Backup** (`backend\executable\AdaptiveSecurityGateway_backup\AdaptiveSecurityGateway.exe`) | 37,883,741 bytes | `4CA9873862332D2DA04908EFDB80503F635A063454B9BFC45760AA9DB2A662F3` | **EXACT MATCH (VERIFIED)** |

### 8.2 Embedded Secrets Finding
- Verified on disk: `backend/executable/AdaptiveSecurityGateway/_internal/.env` is present.
- `AdaptiveSecurityGateway.spec` lines 39-40 explicitly bundle `(str(WORKSPACE_ROOT / ".env"), ".")`.
- If built on a developer system with an active `.env`, the binary embeds local secrets, API keys, and connection strings.

---

## 9. Supply-Chain and CI/CD Audit

### 9.1 Dependency Pinning & Vulnerabilities
- **Python Dependencies:** 17/18 packages in `backend/requirements.txt` and 8/8 in `ml/requirements.txt` use unpinned `>=` constraints. No Python lockfile is committed.
- **Frontend Dependencies:** `package-lock.json` is present. Offline `npm audit` reported 2 high-severity vulnerabilities in developer dependencies:
  - `source-map-js` (GHSA-68fv-2mgg-jv7q: event-loop denial of service).
  - `vite` (GHSA-698v-4r3x-3vcv, GHSA-r825-w8mm-5pxw: command execution via `launch-editor` on Windows).

### 9.2 GitHub Actions Workflows
- **`ci.yml`:** Only executes 10 select test files. Omit auth, RBAC, and service-key suites.
- **`windows-exe-build.yml`:** References non-existent spec file `pyinstaller gateway.spec`. Automated tagging builds will fail.
- **`security-scan.yml`:** Uses `--exit-zero` on Bandit and `|| true` on pip-audit, ignoring security scan failures.

---

## 10. Risk Register with Severity

| Finding ID | Severity | Category | Description | Exact Location | Blocks Prod? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | **CRITICAL** | Authentication | Mock Google OAuth backdoor allows unauthenticated takeover of any user (including ADMIN) | `backend/app/services/auth_service.py:319-327` | **YES** |
| **SEC-02** | **CRITICAL** | Authorization | Unauthenticated public registration allows self-provisioning of `OPERATOR` role | `backend/app/services/auth_service.py:81` | **YES** |
| **SEC-03** | **HIGH** | Configuration | Insecure fallback defaults for `AUTH_JWT_SECRET`, `SECRET_KEY`, and `ADMIN_PASSWORD` not checked in production | `backend/app/config.py:192,289,300,367` | **YES** |
| **SEC-04** | **HIGH** | Packaging | PyInstaller spec and build script bundle developer `.env` file containing secrets into executable | `AdaptiveSecurityGateway.spec:39-40` | **YES** |
| **SEC-05** | **MEDIUM** | CI / Supply Chain | CI workflow only runs 10 test files; omits auth, RBAC, and service key regression tests | `.github/workflows/ci.yml:55` | **NO** |
| **SEC-06** | **MEDIUM** | CI / Supply Chain | Windows executable build workflow invokes non-existent `gateway.spec` | `.github/workflows/windows-exe-build.yml:46` | **NO** |
| **SEC-07** | **MEDIUM** | CI / Supply Chain | Bandit and pip-audit scanners configured with `--exit-zero` and `|| true` | `.github/workflows/security-scan.yml:34,53` | **NO** |
| **SEC-08** | **MEDIUM** | Database | Dual schema creation hazard: `init_db()` calls `create_all`, causing collision with Alembic migrations | `backend/app/main.py:120`, `db/session.py:61` | **NO** |
| **SEC-09** | **MEDIUM** | Authorization | Conflation of firewall allowlist with API authentication allows allowlisted IPs to bypass auth | `backend/app/api/deps.py:185` | **NO** |
| **SEC-10** | **LOW** | Network / Container | Gateway Docker container runs as `root` (UID 0) and retains build toolchain | `deployment/hybrid-lab/gateway/Dockerfile:1` | **NO** |
| **SEC-11** | **LOW** | HTTP Security | Missing modern `Content-Security-Policy` and `Strict-Transport-Security` headers | `backend/app/main.py:186-192` | **NO** |
| **SEC-12** | **LOW** | HTTP Security | Interactive Swagger UI (`/docs`) and ReDoc (`/redoc`) publicly exposed in production | `backend/app/main.py:162-163` | **NO** |
| **SEC-13** | **LOW** | Frontend Auth | Refresh token stored in browser `localStorage` instead of `HttpOnly` cookie | `src/services/auth.ts:37,56` | **NO** |
| **SEC-14** | **INFORMATIONAL** | Supply Chain | Unpinned `>=` Python package dependencies in requirements files | `backend/requirements.txt`, `ml/requirements.txt` | **NO** |

---

## 11. Production Blockers

The following **four findings strictly block approval for production deployment**:

1. **[BLOCKER 1 - CRITICAL] Mock Google Authentication Bypass (`SEC-01`):** Must be excised from `AuthService.handle_google_id_token`. No unauthenticated request should be capable of forging a Google identity.
2. **[BLOCKER 2 - CRITICAL] Self-Assignment of Elevated Roles in Public Signup (`SEC-02`):** `AuthService.signup` must restrict new account roles strictly to `USER` or require administrator privileges to create operators.
3. **[BLOCKER 3 - HIGH] Insecure Production Configuration Defaults (`SEC-03`):** `validate_production_security()` in `backend/app/config.py` must fail closed if `AUTH_JWT_SECRET`, `SECRET_KEY`, or `ADMIN_PASSWORD` are unset or set to development defaults when `APP_ENV=production`.
4. **[BLOCKER 4 - HIGH] Embedded `.env` Secrets in Standalone Executable (`SEC-04`):** PyInstaller specification must not package host `.env` files, and `build_exe.ps1` must not copy host `.env` into binary releases.

---

## 12. Recommended Remediation Order

1. **Step 1 (Immediate - SEC-01 & SEC-02):** Remove `mock_google_` bypass logic from `AuthService.handle_google_id_token` and restrict `AuthService.signup` role assignment to standard `USER`.
2. **Step 2 (Immediate - SEC-03):** Extend `Settings.validate_production_security()` in `backend/app/config.py` to validate `AUTH_JWT_SECRET`, `SECRET_KEY`, and `ADMIN_PASSWORD` against known default values in production.
3. **Step 3 (Immediate - SEC-04):** Update `AdaptiveSecurityGateway.spec` to remove `.env` collection and adjust `build_exe.ps1` to prevent copying developer `.env` files into distribution directories.
4. **Step 4 (Follow-up - SEC-05, SEC-06, SEC-07):** Synchronize `.github/workflows/` so CI runs all 327+ tests, uses `AdaptiveSecurityGateway.spec`, and enforces security scan failures.
5. **Step 5 (Follow-up - SEC-08 & SEC-09):** Remove `Base.metadata.create_all()` in favor of deterministic Alembic execution, and decouple firewall IP allowlists from API authentication.
6. **Step 6 (Hardening - SEC-10, SEC-11, SEC-12, SEC-13):** Add non-root container user, inject CSP/HSTS headers, disable `/docs` in production, and migrate refresh tokens to secure cookies.

---

## 13. Explicit Safety Compliance Statement

In strict adherence to Phase 22.1 directives:
- **Audit-Only Execution:** Zero source code files, configuration files, database schemas, or models were modified.
- **Git State Preservation:** Zero commits, zero pushes, zero stashes, and zero resets were executed. All Phase 21, 21.1, and 22.0 files remain intact in the working tree.
- **No Localhost / Network Probes:** Zero HTTP requests, localhost socket connections, or browser automation were performed.
- **Cloud & Firewall Isolation:** Zero AWS, GCP, or Azure resources were mutated; no host firewall rules were altered; the policy engine remains strictly in safe `DRY_RUN` mode.
- **Database Safety:** Zero migrations, table drops, or record deletions were executed.
- **Phase Boundary:** Phase 22.1 is complete. No Phase 22.2 remediation has been initiated.
