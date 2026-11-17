# Phase 21.1 — Complete API Security Matrix & Authorization Inventory

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `madhumitag06/hybrid-gateway-security`  
**Branch:** `main`  
**Baseline Commit:** `f472588bb35c45031a8a28dec2d19d626ea58daf`  
**Date:** November 16, 2026  

---

## 1. Architectural RBAC Tiering & Authentication Strategy

The Adaptive Security Gateway implements a defense-in-depth authorization hierarchy designed to enforce the principle of least privilege across interactive operators and machine-to-machine integrations:

```
+-------------------------------------------------------------------------------+
|                             ADMINISTRATOR (Tier 4)                           |
|  - Operator user administration & role assignment                              |
|  - Authoritative model promotion & emergency rollbacks                        |
|  - Gateway operational mode modification (DRY_RUN / SANDBOX)                   |
|  - Cloud account provisioning & telemetry checkpoint resets                   |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                               OPERATOR (Tier 3)                               |
|  - Manual containment rule revocation & rollback logging                       |
|  - Benchmark & evaluation suite execution                                     |
|  - Hybrid lab traffic generation scenarios                                    |
|  - Cloud resource discovery & live AWS polling triggers                       |
|  - Training dataset preparation                                               |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                           ANALYST / AUDITOR (Tier 2)                         |
|  - Full read-only visibility into security telemetry & event history          |
|  - Aggregated risk dashboard & time-filtered metrics                          |
|  - On-demand SHAP feature explainability & waterfall attributions             |
|  - Multi-cloud inventory, resource discovery logs & health diagnostics        |
|  - Model registry status & candidate comparison metrics                       |
|  - Ground-truth label verification & feedback curation                        |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                             STANDARD USER (Tier 1)                            |
|  - Read own authenticated profile (`/api/v1/auth/me`)                         |
|  - Update own credentials (`/api/v1/auth/password/change`)                    |
|  - Read notifications marked for personal attention                           |
|  - Strictly forbidden (403 Forbidden) from all operational/analyst routes     |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                       MACHINE-TO-MACHINE / TRUSTED (Tier 0)                   |
|  - Guards: `require_service_or_trusted_network`                               |
|  - Authenticates via:                                                         |
|    1. Bearer JWT access token (Active Analyst / Operator / Admin)             |
|    2. Dedicated `X-API-Key` or `X-Service-Token` matching configured secret    |
|    3. Trusted management allowlist / loopback origin                          |
|  - Endpoints: Real-time flow prediction, PCAP ingestion, CloudWatch batches   |
+-------------------------------------------------------------------------------+
```

---

## 2. Exhaustive API Route Security Matrix

The following matrix documents every active endpoint registered across all gateway routers:

| Method | Endpoint Path | Subsystem | Sensitivity | Authorization Guard | Allowed Roles / Identities | Security Justification & Threat Mitigation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **GET** | `/health` | Health | PUBLIC | None (Sanitized) | Anonymous | Liveness & readiness probes. Sanitized against credential/stack trace disclosure. |
| **GET** | `/api/health` | Health | PUBLIC | None (Sanitized) | Anonymous | Frontend health monitoring alias. |
| **POST** | `/api/v1/auth/signup` | Authentication | PUBLIC | Anonymous | Anonymous | Operator account registration. Enforces bcrypt hashing and password complexity. |
| **POST** | `/api/v1/auth/login` | Authentication | PUBLIC | Anonymous | Anonymous | Credential authentication. Returns short-lived access JWT and refresh token. |
| **POST** | `/api/v1/auth/refresh` | Authentication | PUBLIC | Anonymous | Anonymous | Token rotation endpoint. Validates cryptographically signed refresh tokens. |
| **POST** | `/api/v1/auth/logout` | Authentication | PUBLIC | Anonymous | Anonymous | Revokes active refresh token and invalidates server-side session. |
| **GET** | `/api/v1/auth/me` | Authentication | LOW | `get_current_active_user` | USER, ANALYST, AUDITOR, OPERATOR, ADMIN | Returns identity profile of the authenticated caller. |
| **POST** | `/api/v1/auth/password/change` | Authentication | MEDIUM | `get_current_active_user` | USER, ANALYST, AUDITOR, OPERATOR, ADMIN | Self-service credential rotation. Revokes existing refresh sessions. |
| **GET** | `/api/v1/auth/google/login` | Authentication | PUBLIC | Anonymous | Anonymous | Initiates Google OAuth 2.0 PKCE / state handshake. |
| **GET** | `/api/v1/auth/google/callback` | Authentication | PUBLIC | Anonymous | Anonymous | Completes Google OAuth exchange and issues application JWT. |
| **POST** | `/api/v1/auth/google/token` | Authentication | PUBLIC | Anonymous | Anonymous | Client-side Google ID token verification endpoint. |
| **GET** | `/api/v1/auth/admin/users` | Authentication | CRITICAL | `require_admin` | ADMIN | Lists all registered accounts and roles. Guarded against privilege enumeration. |
| **POST** | `/api/v1/predict` | ML Inference | HIGH | `require_service_or_trusted_network` | Service Key, Trusted Network, or Authenticated User | Automated flow threat inference and continuous risk scoring. Prevents DDoS and unauthorized telemetry injection. |
| **POST** | `/api/v1/predict/batch` | ML Inference | HIGH | `require_service_or_trusted_network` | Service Key, Trusted Network, or Authenticated User | Batch flow evaluation with validation limits (max 500 flows). |
| **GET** | `/api/v1/predict/presets` | ML Inference | LOW | `require_service_or_trusted_network` | Service Key, Trusted Network, or Authenticated User | Returns deterministic sample vectors for interactive verification. |
| **GET** | `/api/dashboard` | Dashboard | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Aggregated composite risk metrics, time-series, and response timeline. |
| **GET** | `/api/v1/dashboard` | Dashboard | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Versioned dashboard aggregation alias. |
| **GET** | `/api/search` | Search | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Unified cross-table incident and policy rule search. |
| **GET** | `/api/v1/search` | Search | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Versioned unified search alias. |
| **GET** | `/api/system/profile` | System | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Gateway profile identity, environment, and uptime metrics. |
| **GET** | `/api/v1/system/profile` | System | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Versioned system profile alias. |
| **GET** | `/api/system/ai-status` | AI Copilot | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | LLM advisory provider status and model configuration. |
| **GET** | `/api/v1/system/ai-status` | AI Copilot | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Versioned AI copilot status alias. |
| **POST** | `/api/events/{id}/ai-briefing` | AI Copilot | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Synthesizes advisory executive summary from SHAP values. |
| **POST** | `/api/v1/events/{id}/ai-briefing` | AI Copilot | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Versioned AI briefing generation alias. |
| **POST** | `/api/notifications/{id}/read` | Notifications | LOW | `get_current_active_user` | USER, ANALYST, AUDITOR, OPERATOR, ADMIN | Marks security notification as read. |
| **POST** | `/api/v1/notifications/{id}/read` | Notifications | LOW | `get_current_active_user` | USER, ANALYST, AUDITOR, OPERATOR, ADMIN | Versioned mark read alias. |
| **POST** | `/api/notifications/read-all` | Notifications | LOW | `get_current_active_user` | USER, ANALYST, AUDITOR, OPERATOR, ADMIN | Bulk marks notifications as read. |
| **POST** | `/api/v1/notifications/read-all` | Notifications | LOW | `get_current_active_user` | USER, ANALYST, AUDITOR, OPERATOR, ADMIN | Versioned bulk read alias. |
| **GET** | `/api/notifications` | Notifications | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Lists high-risk security alert notifications. |
| **GET** | `/api/v1/notifications` | Notifications | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Versioned notifications list alias. |
| **POST** | `/api/events/{id}/action` | Containment | HIGH | `require_operator` | OPERATOR, ADMIN | Updates policy action (Monitor/Restrict/Block) on an incident. |
| **POST** | `/api/v1/events/{id}/action` | Containment | HIGH | `require_operator` | OPERATOR, ADMIN | Versioned incident policy action update alias. |
| **GET** | `/api/v1/events` | Events | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Historical security events with multi-attribute filtering and pagination. |
| **GET** | `/api/v1/events/{id}` | Events | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Complete flow feature vector and class probabilities for an incident. |
| **GET** | `/api/v1/events/{id}/history` | Audit | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Immutable policy modification history for compliance auditing. |
| **GET** | `/api/v1/events/{id}/explanation` | Explainability | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | On-demand SHAP waterfall feature attributions for an incident. |
| **GET** | `/api/v1/analytics/summary` | Analytics | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Threat distributions, histogram buckets, and provenance metrics. |
| **POST** | `/api/v1/analytics/explain-flow` | Explainability | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Computes SHAP attributions for arbitrary synthetic flow vectors. |
| **GET** | `/api/v1/enforcement/rules` | Containment | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Active, simulated, and revoked containment rules with remaining TTLs. |
| **POST** | `/api/v1/enforcement/rules/{id}/revoke` | Containment | HIGH | `require_operator` | OPERATOR, ADMIN | Manually revokes containment rule and records immutable audit ledger. |
| **GET** | `/api/v1/enforcement/config` | Configuration | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Gateway mode (DRY_RUN/SANDBOX), allowlist, and default TTL settings. |
| **PUT** | `/api/v1/enforcement/config` | Configuration | CRITICAL | `require_admin` | ADMIN | Mutates gateway mode or allowlist. Guarded against unauthorized mode switches. |
| **POST** | `/api/v1/policies/evaluate` | Policy | HIGH | `require_service_or_trusted_network` | Service Key, Trusted Network, or Authenticated User | Context-aware policy evaluation engine. |
| **POST** | `/api/v1/policies/compare` | Policy | HIGH | `require_service_or_trusted_network` | Service Key, Trusted Network, or Authenticated User | Static baseline vs. Adaptive AI decision comparison. |
| **GET** | `/api/v1/enforcement/audit` | Audit | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Chronological audit trail of all policy actions and revocations. |
| **GET** | `/api/v1/shadow/status` | Shadow Mode | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Candidate model operational configuration and status. |
| **GET** | `/api/v1/shadow/comparison` | Shadow Mode | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Model agreement rate, latency distributions, and disagreement categories. |
| **GET** | `/api/v1/shadow/records` | Shadow Mode | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Paginated shadow prediction comparison records. |
| **GET** | `/api/v1/shadow/registry` | Model Lifecycle | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Active and standby model versions and feature schema metadata. |
| **POST** | `/api/v1/shadow/promote` | Model Lifecycle | CRITICAL | `require_admin` | ADMIN | Promotes candidate model version to primary authority. Guarded against unauthorized model swapping. |
| **POST** | `/api/v1/shadow/rollback` | Model Lifecycle | CRITICAL | `require_admin` | ADMIN | Emergency zero-downtime rollback to standby model. |
| **GET** | `/api/v1/adaptive/telemetry` | Adaptive ML | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Aggregate verified feedback counts and training run metrics. |
| **GET** | `/api/v1/adaptive/feedbacks` | Adaptive ML | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Paginated list of flow records queued for analyst ground-truth review. |
| **POST** | `/api/v1/adaptive/feedback` | Adaptive ML | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Submits analyst confirmation or correction of flow threat label. |
| **POST** | `/api/v1/adaptive/dataset/prepare` | Adaptive ML | HIGH | `require_operator` | OPERATOR, ADMIN | Validates verified labels and class balance for retraining dataset. |
| **POST** | `/api/v1/adaptive/train` | Adaptive ML | CRITICAL | `require_admin` | ADMIN | Initiates isolated candidate retraining in sandbox directory. |
| **GET** | `/api/v1/adaptive/runs` | Adaptive ML | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Retraining run history, evaluation accuracy, and candidate version IDs. |
| **POST** | `/api/v1/adaptive/promote` | Adaptive ML | CRITICAL | `require_admin` | ADMIN | Approves evaluated retraining run for production promotion. |
| **POST** | `/api/v1/adaptive/rollback` | Adaptive ML | CRITICAL | `require_admin` | ADMIN | Rolls back active model to previous standby version. |
| **GET** | `/api/v1/cloud/providers` | Multi-Cloud | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Supported cloud provider capability matrix (AWS, GCP, Azure, Lab). |
| **GET** | `/api/v1/cloud/accounts` | Multi-Cloud | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Configured cloud accounts and connection latencies. |
| **POST** | `/api/v1/cloud/accounts` | Multi-Cloud | CRITICAL | `require_admin` | ADMIN | Adds or mutates cloud account credentials and IAM role ARNs. |
| **POST** | `/api/v1/cloud/accounts/{provider}/test-connection` | Multi-Cloud | HIGH | `require_operator` | OPERATOR, ADMIN | Tests live STS caller identity and credentials for a provider. |
| **POST** | `/api/v1/cloud/accounts/AWS/discover` | Multi-Cloud | HIGH | `require_operator` | OPERATOR, ADMIN | Triggers read-only discovery of VPCs, Subnets, and Security Groups. |
| **GET** | `/api/v1/cloud/accounts/AWS/flow-logs` | Multi-Cloud | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Active CloudWatch Logs and S3 flow log subscriptions. |
| **POST** | `/api/v1/cloud/accounts/AWS/poll-telemetry` | Multi-Cloud | HIGH | `require_operator` | OPERATOR, ADMIN | Polls live CloudWatch/S3 flow log events and executes ML detection. |
| **GET** | `/api/v1/cloud/accounts/AWS/telemetry-status` | Multi-Cloud | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Checkpoint status, active log groups, and ingestion health. |
| **GET** | `/api/v1/cloud/accounts/AWS/telemetry-history` | Multi-Cloud | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Chronological history of past CloudWatch polling batches. |
| **POST** | `/api/v1/cloud/accounts/AWS/telemetry-checkpoints/reset` | Multi-Cloud | CRITICAL | `require_admin` | ADMIN | Resets CloudWatch telemetry watermark to allow re-ingestion. |
| **GET** | `/api/v1/cloud/resources` | Multi-Cloud | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Inventory of discovered network resources across all cloud providers. |
| **GET** | `/api/v1/cloud/inventory/summary` | Multi-Cloud | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Cross-cloud resource counts by type and provider. |
| **POST** | `/api/v1/cloud/telemetry/ingest` | Multi-Cloud | HIGH | `require_service_or_trusted_network` | Service Key, Trusted Network, or Authenticated User | Normalizes raw VPC log batches into canonical 9-feature schema. |
| **GET** | `/api/v1/cloud/health` | Multi-Cloud | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Live connection health across AWS, GCP, Azure, and Lab adapters. |
| **GET** | `/api/v1/hybrid/topology` | Hybrid | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Configured On-Premises and AWS VPC CIDR ranges and boundaries. |
| **GET** | `/api/v1/hybrid/telemetry-status` | Hybrid | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Hybrid telemetry state (offline fixture vs. read-only CloudWatch). |
| **GET** | `/api/v1/hybrid/lab-status` | Hybrid | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Virtual hybrid lab topology, container health, and event counters. |
| **GET** | `/api/v1/hybrid/samples` | Hybrid | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Pre-packaged reproducible AWS VPC Flow Log benchmark scenarios. |
| **POST** | `/api/v1/hybrid/ingest-vpc-logs` | Hybrid | HIGH | `require_service_or_trusted_network` | Service Key, Trusted Network, or Authenticated User | Direct raw VPC log parser, ML inference, and DB persistence. |
| **POST** | `/api/v1/hybrid/upload-vpc-file` | Hybrid | HIGH | `require_service_or_trusted_network` | Service Key, Trusted Network, or Authenticated User | File upload handler for `.log`, `.txt`, `.tsv` VPC flow logs. |
| **POST** | `/api/v1/hybrid/samples/{id}/ingest` | Hybrid | HIGH | `require_operator` | OPERATOR, ADMIN | Executes benchmark AWS VPC flow fixture. |
| **GET** | `/api/v1/hybrid/scenarios` | Hybrid | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Lists 6 cross-boundary traffic generation scenarios. |
| **POST** | `/api/v1/hybrid/scenarios/{id}/run` | Hybrid | HIGH | `require_operator` | OPERATOR, ADMIN | Triggers real cross-network traffic generation in lab containers. |
| **GET** | `/api/v1/hybrid/infrastructure/health` | Hybrid | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Status of 13 Docker services in virtual hybrid cloud lab. |
| **GET** | `/api/v1/ingest/status` | Ingestion | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | PCAP ingestion engine operational status and packet counters. |
| **GET** | `/api/v1/ingest/samples` | Ingestion | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Pre-packaged demonstration PCAP fixtures. |
| **POST** | `/api/v1/ingest/samples/{name}` | Ingestion | HIGH | `require_operator` | OPERATOR, ADMIN | Ingests and evaluates sample PCAP capture. |
| **POST** | `/api/v1/ingest/pcap` | Ingestion | HIGH | `require_service_or_trusted_network` | Service Key, Trusted Network, or Authenticated User | Uploads and processes PCAP/PCAPNG network trace file (max 15MB). |
| **GET** | `/api/v1/ingest/latest` | Ingestion | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Most recent completed PCAP ingestion run record. |
| **GET** | `/api/v1/ingest/history` | Ingestion | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Paginated history of past PCAP upload runs. |
| **GET** | `/api/v1/ingest/history/{id}` | Ingestion | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Detailed flow metrics for a specific PCAP ingestion run. |
| **GET** | `/api/v1/evaluation/suites` | Benchmarking | LOW | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Predefined benchmark scenario suites and sample counts. |
| **POST** | `/api/v1/evaluation/run` | Benchmarking | HIGH | `require_operator` | OPERATOR, ADMIN | Runs dual comparative evaluation (Adaptive AI vs. Static Baseline). |
| **GET** | `/api/v1/evaluation/export` | Benchmarking | MEDIUM | `require_analyst` | ANALYST, AUDITOR, OPERATOR, ADMIN | Exports benchmark evaluation metrics in JSON or CSV format. |

---

## 3. Defense-in-Depth HTTP Headers Verification

Every response issued by the Gateway is enriched with mandatory enterprise HTTP security headers implemented in `backend/app/main.py`:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

These headers protect operators against MIME confusion, UI clickjacking, reflective cross-site scripting, and unauthorized browser feature delegation.
