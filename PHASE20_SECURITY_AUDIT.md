# Phase 20 — Application Security & Configuration Audit Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Date:** November 16, 2026  
**Focus:** Workstreams A (Application Security) and B (Secrets and Configuration)  
**Execution Mode:** STRICT READ-ONLY FORENSIC AUDIT  

---

## 1. Authentication, Sessions & Cryptography Audit

### 1.1 Password Hashing & Storage
- **Mechanism:** Bcrypt password hashing (`bcrypt.hashpw`) utilizing random salts generated with work factor 12 (`rounds=12`).
- **Timing Attacks:** Plaintext verification via `bcrypt.checkpw()` executes in constant-time relative to password length, mitigating timing side-channel attacks.
- **Null / Empty Handling:** `verify_password()` defensively returns `False` if either password or hash is null or empty.

### 1.2 JWT Token Lifecycle & Rotation
- **Access Tokens:** Signed via HMAC-SHA256 (`HS256`) using `auth_jwt_secret`. Default lifetime: 60 minutes (`auth_access_token_expire_minutes`). Payload includes `sub` (user UUID), `jti` (unique token UUID), `exp`, `iat`, `type="access"`, and `iss="hybrid-gateway-security"`.
- **Refresh Tokens:** Long-lived signed JWTs (7-day default TTL) tracked in the PostgreSQL `refresh_tokens` table.
- **Token Rotation:** Every call to `/api/v1/auth/refresh` immediately invalidates the supplied refresh token (`is_revoked=True`) and issues a fresh token pair.
- **Session Termination:** Password changes via `/api/v1/auth/password/change` automatically revoke all outstanding refresh tokens for the operator (`revoke_all_for_user`).

---

## 2. Authorization & Role-Based Access Control (RBAC)

### 2.1 Role Hierarchy
The gateway defines five operational roles:
1. `ADMIN`: Full system administrative authority, user account management, model promotion, and enforcement configuration.
2. `OPERATOR`: Active gateway operations, flow ingestion, and containment rule management.
3. `ANALYST`: Forensic read-only inspection, event queries, explainability benchmarks, and policy comparison.
4. `AUDITOR`: Immutable audit log queries and policy compliance validation.
5. `USER`: Basic telemetry consumption.

### 2.2 Endpoint Authorization Coverage Audit
A line-by-line inspection of backend route definitions revealed the following authorization coverage:

| Endpoint Route | HTTP Method | Sensitivity | Current Auth Dependency | Recommended Policy |
| :--- | :---: | :---: | :---: | :--- |
| `/api/v1/auth/admin/users` | `GET` | Administrative | `require_admin` | **ADEQUATE** |
| `/api/v1/auth/me` | `GET` | Operator Profile | `get_current_active_user` | **ADEQUATE** |
| `/api/v1/auth/password/change` | `POST` | Sensitive Action | `get_current_active_user` | **ADEQUATE** |
| `/api/v1/shadow/promote` | `POST` | Critical ML Lifecycle | None (Open) | **FLAGGED — HIGH RISK** |
| `/api/v1/shadow/rollback` | `POST` | Critical ML Lifecycle | None (Open) | **FLAGGED — HIGH RISK** |
| `/api/v1/enforcement/config` | `PUT` | Critical Gateway Mode | None (Open) | **FLAGGED — HIGH RISK** |
| `/api/v1/enforcement/rules/{id}/revoke`| `POST` | Containment Lifecycle | None (Open) | **FLAGGED — MEDIUM RISK** |
| `/api/v1/adaptive/deploy-model` | `POST` | Retraining Deployment | None (Open) | **FLAGGED — HIGH RISK** |
| `/api/v1/predict` | `POST` | Telemetry Ingestion | Optional / None | **ADEQUATE** (Agent Ingress) |
| `/api/v1/ingest/pcap` | `POST` | Telemetry Ingestion | None (File Upload) | **ADEQUATE** (15MB Limit) |

---

## 3. Network Security, CORS & HTTP Headers

### 3.1 CORS Configuration
CORS middleware in `backend/app/main.py` is configured via:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
```
- **Evaluation:** `settings.cors_origins` defaults to local loopback development origins (`localhost:5173`, `127.0.0.1:5173`, `localhost:3000`). It is configurable via `CORS_ORIGINS` environment variable.
- **Finding:** Wildcard `*` is not used in production when origins are specified.

### 3.2 HTTP Security Response Headers
- **Evaluation:** Currently, the FastAPI application lacks an HTTP security headers middleware.
- **Risk:** Browsers communicating with the gateway frontend or API are not instructed to enforce MIME-type sniffing protections or frame embedding restrictions.
- **Remediation:** Introduce standard security response headers:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: geolocation=(), camera=(), microphone=()`

---

## 4. Input Validation & Injection Risks

### 4.1 SQL Injection
- **Evaluation:** All database queries utilize SQLAlchemy ORM mapped models and parameterized `select()` constructs with bound parameters.
- **Audit Result:** Zero raw SQL string interpolations (`f"SELECT ... {param}"`) exist across the entire backend code base. SQL injection risk is **NEGLIGIBLE**.

### 4.2 Deserialization Safety
- **Evaluation:** Network flow JSON payloads are parsed strictly via Pydantic schemas (`NetworkFlowRequest`, `CanonicalFlowRecord`).
- **Audit Result:** `pickle.loads` is completely absent from backend application services. Model loading (`joblib.load`) operates strictly on static, signed local files residing in protected application directories.

### 4.3 Request Size & DoS Protection
- **PCAP File Uploads:** Strictly clamped to 15 MB (`MAX_UPLOAD_SIZE_BYTES = 15 * 1024 * 1024`) with chunked reads and automated temporary file cleanup.
- **Batch Endpoints:** `BatchPredictionRequest.flows` and `CloudTelemetryBatchRequest.records` currently lack an upper length constraint (`max_length`). Imposing `max_length=500` prevents memory exhaustion attacks.

---

## 5. Secrets Management & Default Credentials

### 5.1 Hardcoded Password Residues in `AuthService`
In `backend/app/services/auth_service.py` (lines 110–121):
```python
if not password_valid and user.role == "ADMIN":
    req_email = req.email.strip().lower()
    admin_cfg_email = settings.admin_email.strip().lower()
    if req_email == admin_cfg_email and req.password in (settings.admin_password, "test@123", "AdminSecOps2026!"):
        user.password_hash = hash_password(settings.admin_password)
        user_repo.update(user)
        password_valid = True
    elif req_email == "admin@gateway.local" and req.password in ("AdminSecOps2026!", "AdminSecret2026!"):
        user.password_hash = hash_password("AdminSecOps2026!")
        user_repo.update(user)
        password_valid = True
```
- **Severity: HIGH**
- **Impact:** Hardcoded strings `"test@123"`, `"AdminSecOps2026!"`, and `"AdminSecret2026!"` act as backdoor credentials if the administrator account is created with these emails.
- **Remediation:** Remove all hardcoded password strings. Administrator authentication must validate strictly against `user.password_hash` or environment-configured `settings.admin_password`.

### 5.2 Safe Production Configuration Checklist

Before promoting the gateway to a live production environment, operators must verify:
- [ ] `SECRET_KEY` set to a high-entropy 256-bit random hex string.
- [ ] `AUTH_JWT_SECRET` set to an independent 256-bit random hex string (minimum 32 characters).
- [ ] `DEBUG` explicitly set to `False`.
- [ ] `ADMIN_PASSWORD` configured with a strong passphrase (minimum 14 characters with mixed case, digits, and symbols).
- [ ] `CORS_ORIGINS` restricted to verified enterprise domain origins.
- [ ] `DATABASE_URL` configured with TLS (`sslmode=require` or `sslmode=verify-full`).
- [ ] Real AWS credentials configured strictly through IAM roles / instance profiles rather than long-lived access keys.
- [ ] `DEFAULT_ENFORCEMENT_MODE` maintained in `DRY_RUN` until security policies are formally baseline-approved.
