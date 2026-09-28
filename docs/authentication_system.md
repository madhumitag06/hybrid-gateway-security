# Phase 13: Full Authentication & User Account System Architecture

## 1. Executive Summary

The **Adaptive AI-Powered Security Gateway for Hybrid Cloud** implements a production-grade, multi-user authentication and identity management system. The application no longer launches directly into the Security Operations Console; instead, all unauthenticated access is intercepted by a Zero-Trust frontend route guard (`AuthView`) backed by FastAPI authentication endpoints and PostgreSQL identity tables.

### Key Capabilities
- **Local Email/Password Authentication**: User registration, password complexity validation, secure bcrypt password hashing, and login verification.
- **Cryptographic JWT Sessions**: Short-lived Access Tokens (30 minutes default) paired with cryptographically unique, rotated Refresh Tokens (7 days default) with database-backed revocation.
- **Initial Administrator Bootstrap**: Environment-configurable administrator bootstrap (`ADMIN_EMAIL` and `ADMIN_PASSWORD`) ensuring safe, idempotent initial provisioning with PostgreSQL-backed role persistence.
- **Role-Based Authorization Guards**: Granular backend permissions for `ADMIN`, `ANALYST`, and `USER` roles, protecting administrative operations and multi-tenant security views.
- **Google OAuth 2.0 / OpenID Connect**: Optional Google Workspace / Google OAuth integration with server-side signature validation and safe local account linking.
- **Dynamic SecOps Profile Identity**: Replacement of prototype console labels with real, verified database identities (Operator Name, Role Badge, Email, Auth Provider, Account Timestamps).
- **Strict Decoupling from Authoritative Security**: Authentication resides exclusively at the application/API access boundary, ensuring zero impact on real-time ML threat detection, SHAP explainability, or automated policy enforcement.

---

## 2. System Architecture & Component Diagram

```mermaid
graph TD
    Client[React SecOps Console] -->|Unauthenticated| AuthScreen[AuthView / Login / Signup]
    Client -->|Authenticated Bearer JWT| APIGateway[FastAPI Auth & Operations Router]
    
    subgraph AuthLayer [Authentication & Identity Subsystem]
        APIGateway -->|POST /api/v1/auth/signup| AuthService
        APIGateway -->|POST /api/v1/auth/login| AuthService
        APIGateway -->|POST /api/v1/auth/refresh| AuthService
        APIGateway -->|GET /api/v1/auth/admin/users| AdminGuard[require_admin Dependency]
        AuthService --> SecurityUtils[Bcrypt Hash & JWT HMAC-SHA256]
        AuthService --> UserRepo[UserRepository / RefreshTokenRepository]
        UserRepo --> PostgreSQL[(PostgreSQL Database: users, refresh_tokens)]
    end

    subgraph SecurityPipeline [Authoritative Security Pipeline (Independent)]
        Telemetry[Network / PCAP / AWS VPC] --> FeatureExtraction[Feature Extraction]
        FeatureExtraction --> MLInference[Random Forest Classifier]
        MLInference --> RiskScore[Continuous Risk Scoring]
        RiskScore --> SHAP[SHAP Feature Attribution]
        SHAP --> PolicyEngine[PolicyEngine Decision Matrix]
        PolicyEngine --> Enforcement[Enforcement Sandbox Adapter]
        Enforcement --> EventLog[(PostgreSQL security_events)]
    end
```

---

## 3. Database Schema & Alembic Migration

The authentication data model is managed via Alembic migration `backend/alembic/versions/003_auth_users.py`.

### `users` Table
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `VARCHAR(64)` | `PRIMARY KEY` | UUIDv4 unique operator identifier |
| `email` | `VARCHAR(255)` | `UNIQUE`, `NOT NULL`, `INDEX` | Normalized corporate/operator email |
| `password_hash` | `VARCHAR(255)` | `NULLABLE` | Bcrypt salted hash (null for OAuth-only users) |
| `full_name` | `VARCHAR(255)` | `NOT NULL` | Full display name of the operator |
| `role` | `VARCHAR(32)` | `NOT NULL`, `INDEX` | `ADMIN`, `ANALYST`, or `USER` |
| `auth_provider` | `VARCHAR(32)` | `NOT NULL`, `INDEX` | `LOCAL` or `GOOGLE` |
| `google_subject_id` | `VARCHAR(255)` | `NULLABLE`, `INDEX` | Google OpenID `sub` claim for federated linking |
| `is_active` | `BOOLEAN` | `NOT NULL`, `DEFAULT TRUE` | Account activation flag |
| `is_verified` | `BOOLEAN` | `NOT NULL`, `DEFAULT TRUE` | Email verification flag |
| `last_login_at` | `TIMESTAMPTZ` | `NULLABLE` | Timestamp of most recent authentication |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` | Account creation timestamp |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL` | Last update timestamp |

### `refresh_tokens` Table
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `VARCHAR(64)` | `PRIMARY KEY` | UUIDv4 session record identifier |
| `user_id` | `VARCHAR(64)` | `FOREIGN KEY (users.id) ON DELETE CASCADE` | Linked operator account |
| `token` | `VARCHAR(512)` | `UNIQUE`, `NOT NULL`, `INDEX` | Signed JWT refresh token string |
| `expires_at` | `TIMESTAMPTZ` | `NOT NULL`, `INDEX` | Token expiration timestamp |
| `is_revoked` | `BOOLEAN` | `NOT NULL`, `DEFAULT FALSE` | Token revocation status |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` | Issuance timestamp |

---

## 4. API Endpoints Reference

All authentication routes are accessible under `/api/v1/auth` and `/api/auth`:

| Method | Path | Access | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/signup` | Public | Register a new operator account and issue JWT token pair |
| `POST` | `/api/v1/auth/login` | Public | Authenticate email/password and issue JWT token pair |
| `POST` | `/api/v1/auth/refresh` | Public | Rotate refresh token and issue new access/refresh tokens |
| `POST` | `/api/v1/auth/logout` | Authenticated | Revoke refresh token and terminate active session |
| `GET` | `/api/v1/auth/me` | Authenticated | Return authenticated profile details |
| `POST` | `/api/v1/auth/password/change` | Authenticated | Change account password after verifying current password |
| `GET` | `/api/v1/auth/google/login` | Public | Initialize Google OAuth 2.0 flow or check provider status |
| `GET` | `/api/v1/auth/google/callback` | Public | Handle Google OAuth code callback and exchange for session |
| `POST` | `/api/v1/auth/google/token` | Public | Exchange Google ID token for authenticated gateway session |
| `GET` | `/api/v1/auth/admin/users` | **Admin Only** | List all registered accounts and roles |

---

## 5. Environment Configuration

Add the following variables to `.env` (derived from `.env.example`):

```bash
# JWT Session Security
AUTH_JWT_SECRET=production-grade-random-entropy-signing-secret
AUTH_JWT_ALGORITHM=HS256
AUTH_ACCESS_TOKEN_EXPIRE_MINUTES=30
AUTH_REFRESH_TOKEN_EXPIRE_DAYS=7

# Initial Administrator Bootstrap (PostgreSQL-Backed)
ADMIN_EMAIL=admin@gateway.local
ADMIN_PASSWORD=AdminSecOps2026!

# Google OAuth 2.0 / OpenID Connect (Optional)
GOOGLE_OAUTH_ENABLED=false
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:5173
```

---

## 6. Google OAuth 2.0 Setup Guide

To enable Google Single Sign-On (SSO):
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Create an **OAuth 2.0 Client ID** (Application type: **Web application**).
3. Add **Authorized Javascript origins**: `http://localhost:5173` and `http://localhost:8000`.
4. Add **Authorized redirect URIs**: `http://localhost:5173` and `http://localhost:8000/api/v1/auth/google/callback`.
5. Set `GOOGLE_OAUTH_ENABLED=true`, `GOOGLE_CLIENT_ID`, and `GOOGLE_CLIENT_SECRET` in `.env`.
6. Restart the backend. The "Continue with Google" button will activate automatically. If credentials are not set, the application operates in 100% functional local authentication mode without error.

---

## 7. Verification and Automated Testing

Run the backend test suite:
```powershell
.\ml\.venv\Scripts\pytest.exe -q
```
*Result: 133 passed (100% passing across ML, analytics, database, and auth suites).*

Run the frontend build:
```powershell
npm.cmd run build
```
*Result: TypeScript build and Vite bundle compiled cleanly with 0 errors.*
