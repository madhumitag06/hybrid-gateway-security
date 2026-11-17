# Adaptive AI-Powered Security Gateway for Hybrid Cloud
## Authoritative Architecture, Intelligence & Multi-Cloud Reference

**Version:** 1.0.0 (Production Release Candidate)  
**Classification:** Enterprise Hybrid-Cloud Security Gateway & Distributed Defense Architecture  
**Document Ownership:** Architecture, Security & Engineering Review Board  

---

# 1. Executive Summary & Vision

The **Adaptive AI-Powered Security Gateway for Hybrid Cloud** is an enterprise-grade defense orchestration platform designed to unify network visibility, zero-trust telemetry harvesting, real-time machine learning threat classification, explainable AI (XAI), and multi-cloud perimeter governance.

Modern enterprise networks span heterogeneous boundaries: on-premises data centers, containerized Kubernetes/Docker workloads, and multiple public cloud providers (Amazon Web Services, Google Cloud Platform, Microsoft Azure). Traditional perimeter solutions suffer from fragmented visibility, vendor lock-in, unnormalized logging formats, and high false-positive rates.

This platform bridges this divide by providing:
1. **Canonical Zero-Trust Telemetry Normalization**: Ingestion of AWS VPC Flow Logs, GCP VPC Flow Logs, Azure NSG Flow Events, and on-premises PCAP/NetFlow streams into a standardized 9-feature schema.
2. **High-Fidelity AI/ML Threat Classification**: Real-time multiclass inference using a trained XGBoost V2 model that detects reconnaissance (port scans), denial of service (traffic spikes), credential stuffing (brute force), and suspicious data exfiltration.
3. **Transparent Explainability (XAI)**: Local feature attribution via TreeSHAP waterfall charts, explaining the specific networking attributes that contributed to threat classification.
4. **Envelope-Encrypted Cloud Credential Vault**: Hardened AES-256-GCM authenticated encryption for AWS STS credentials, GCP service accounts, and Azure Entra ID app secrets.
5. **Multi-Tier Automated Containment**: Safe dry-run simulation and automated containment dispatch (iptables forward drop, null-routes, cloud security group updates) with automated TTL revocation.

---

# 2. System Architecture & Topology

The platform comprises a modular distributed architecture deployed either via Docker Compose or as a standalone native Windows executable bundle.

```
+-----------------------------------------------------------------------------------+
|                                PRESENTATION TIER                                  |
|   React 19 + TypeScript + Vite + Canonical Art-Directed Theme (CSS Custom Props)  |
|   5 Collapsible Navigation Groups | 7 Multi-Cloud Sub-Tabs | SHAP Visualizer     |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          | JSON / REST API (JWT Authenticated)
                                          v
+-----------------------------------------------------------------------------------+
|                               APPLICATION GATEWAY                                 |
|   FastAPI (Python 3.12) | Uvicorn ASGI | Dependency Injection Engine             |
|   - Multi-Cloud Identity & Resource Registry                                      |
|   - Telemetry Ingestion, SHA-256 Deduplication & Checkpoint Pipeline             |
|   - Policy & Enforcement State Machine (DRY_RUN / SANDBOX / LIVE)                |
|   - AES-256-GCM Envelope Encryption Credential Vault                              |
+-------------------+---------------------+--------------------+--------------------+
                    |                     |                    |
                    v                     v                    v
+-----------------------+ +---------------------+ +-------------------------------+
|     DATA LAYER        | |      AI ENGINE      | |       CLOUD ADAPTERS          |
| PostgreSQL 16.3 /     | | XGBoost V2 Canonical| | AWS STS & CloudWatch Ingest   |
| SQLite Local          | | TreeSHAP Explainer  | | GCP Builders Hub & VPC SC     |
| Alembic Migrations    | | 9-Feature Pipeline  | | Azure Entra ID & NSG Flow     |
| (001 through 005)     | | Model Registry      | | Docker Lab Linux iptables     |
+-----------------------+ +---------------------+ +-------------------------------+
```

---

# 3. Machine Learning Threat Detection Engine

### 3.1 Canonical 9-Feature Feature Schema
The threat detection engine uses an XGBoost V2 gradient-boosted decision tree architecture. The model is trained on cross-environment hybrid flow telemetry normalized into 9 strictly observed physical network dimensions:

| Feature Name | Data Type | Physical Meaning | Normalization Bounds |
|---|---|---|---|
| `packet_count` | Integer | Total packets transferred during flow window | Clamped $[1, 10^7]$ |
| `byte_count` | Integer | Total bytes transferred during flow window | Clamped $[20, 10^{10}]$ |
| `duration` | Float | Session duration in seconds | Clamped $[0.001, 86400.0]$ |
| `conn_rate` | Float | Connection attempts per second | Clamped $[0.0, 100000.0]$ |
| `dst_port` | Integer | Destination TCP/UDP port number | Normalized $[0, 65535]$ |
| `unique_dst_ports` | Integer | Distinct destination ports targeted in time window | Observed $[1, 1000]$ |
| `flow_count` | Integer | Number of aggregated flows from source IP | Observed $[1, 10000]$ |
| `protocol_type` | Integer | Transport protocol (6 = TCP, 17 = UDP, 1 = ICMP) | Categorical integer |
| `direction` | Integer | Flow directionality (0 = Inbound, 1 = Outbound, 2 = Internal) | Discrete mapping |

> **Design Principle**: Synthetic variables (such as synthetic `failed_auth_count`) have been completely eradicated from feature extractors. Telemetry parsers strictly compute genuine network invariants.

### 3.2 Multiclass Attack Taxonomy
The model classifies flows into five categories:
1. `BENIGN`: Standard legitimate traffic.
2. `PORT_SCAN`: Multi-port reconnaissance sweeps across subnets.
3. `TRAFFIC_SPIKE`: Sudden volumetric bursts resembling denial of service.
4. `SUSPICIOUS_TRANSFER`: High-volume or atypical outbound egress flows.
5. `BRUTE_FORCE`: Rapid repetitive connection bursts targeting authentication ports (SSH, RDP, HTTPS).

### 3.3 Explainability (XAI) & TreeSHAP
For every high-risk inference (Risk Score $\ge 70/100$), the gateway computes exact SHAP feature attributions using `shap.TreeExplainer`. The frontend displays:
- Base expected log-odds value.
- Positive attribution factors (features driving the risk score up).
- Negative attribution factors (features keeping the risk score down).
- Plain-English natural language summaries detailing why the flow was flagged.

---

# 4. Multi-Cloud Architecture & Onboarding

### 4.1 Supported Platforms
- **Amazon Web Services (AWS)**: STS AssumeRole authentication with `ExternalId`, VPC Flow Logs harvesting from CloudWatch Logs and S3 buckets, and EC2 topology discovery.
- **Google Cloud Platform (GCP)**: Service Account JSON key authentication, VPC Service Controls, Builders Hub compute and subnetwork inventory.
- **Microsoft Azure**: Entra ID App Registration (`tenant_id`, `client_id`, `client_secret`), Network Security Groups (NSG) Flow Logs, and Virtual Network peering.
- **Docker Hybrid Lab**: Local containerized bridge router with iptables FORWARD table isolation.

### 4.2 AES-256-GCM Envelope Encryption Credential Vault
All cloud credentials (AWS secret keys, GCP private keys, Azure client secrets) are encrypted before entering database storage:
- **Cipher**: AES-256-GCM (Galois/Counter Mode).
- **IV / Nonce**: 12-byte cryptographically secure pseudorandom nonce generated per operation via `os.urandom(12)`.
- **Authentication Tag**: 16-byte MAC tag verifying both ciphertext integrity and authenticity.
- **Key Derivation**: HKDF-SHA256 derived from the master configuration encryption key (`CLOUD_CREDENTIAL_ENCRYPTION_KEY`).
- **Metadata Separation**: Non-secret attributes (account name, region, environment tag, resource counts) are stored unencrypted in `cloud_accounts` table. Plaintext secret materials are stored exclusively as base64-encoded ciphertext in `cloud_credential_vault`.

---

# 5. Security & Containment State Machine

### 5.1 Operating Modes
1. `DRY_RUN`: Safe analysis mode. Rules, alerts, and metrics are computed and visualized in the UI, but no active system commands or network blocks are executed on the host.
2. `SANDBOX`: Safe containerized execution inside the Docker lab cluster.
3. `LIVE`: Production enforcement mode where isolation rules are actively applied to Linux packet filtering or cloud security groups.

### 5.2 Automated Containment Lifecycle
When high-risk threats trigger policy enforcement:
- An `EnforcementRule` is created with a configurable Time-To-Live (default 300 seconds).
- The action (`DROP`, `NULL_ROUTE`, `RATE_LIMIT`) is dispatched to the provider adapter.
- The rule status transitions through `ACTIVE` $\to$ `EXPIRED` $\to$ `REVOKED`.
- Expired rules are automatically culled by background daemon workers.

---

# 6. Database Schema & Alembic Revisions

The persistence layer uses SQLAlchemy 2.0 with Alembic versioning:
- `001_initial_schema`: Core security events, policies, and system status.
- `002_pcap_ingestion`: PCAP uploads, session tracking, and packet metadata.
- `003_auth_users`: User identities, hashed credentials (bcrypt), RBAC roles (`admin`, `analyst`, `user`).
- `004_enterprise_schema`: Multi-cloud account registry, discovered network resources, flow checkpoints.
- `005_cloud_credentials`: AES-256-GCM credential vault, encryption key versioning, ownership relationships.
