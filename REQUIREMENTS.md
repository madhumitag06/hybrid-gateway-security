# Adaptive AI-Powered Security Gateway for Hybrid Cloud
## Formal System, Runtime & Security Requirements Specification

**Version:** 1.0.0 (Production Release Candidate)  
**Standard:** IEEE 830-1998 / ISO/IEC/IEEE 29148:2018 Compliant  

---

# 1. Hardware & Operating System Requirements

### 1.1 Minimum Workstation & Server Specifications
- **Operating System**: Windows 10 (Build 19044+) 64-bit, Windows 11, or Linux (Kernel 5.15+ x86_64).
- **Processor**: 4 x86_64 Cores with AVX2 instruction support (required for vectorized XGBoost inference).
- **System Memory (RAM)**: 8 GB minimum, 16 GB recommended for concurrent multi-container lab execution.
- **Persistent Storage**: 10 GB available SSD storage.
- **Network Interface**: Gigabit Ethernet or 802.11ac+ wireless interface.

---

# 2. Network Port Allocation & Firewall Rules

The application uses deterministic loopback and container port allocations:

| Port | Protocol | Binding | Service Component | Description |
|---|---|---|---|---|
| **8000** | TCP | `127.0.0.1` / `0.0.0.0` | `gateway-api` | FastAPI REST & Ingestion API Server |
| **5173** | TCP | `127.0.0.1` | `frontend (Vite Dev)` | Vite Hot-Reloading Development Server |
| **5175** | TCP | `127.0.0.1` / `0.0.0.0` | `frontend (Docker)` | Production Nginx / Containerized Frontend |
| **5434** | TCP | `127.0.0.1` / `0.0.0.0` | `postgres` | PostgreSQL Relational Database Server |
| **8099** | TCP | `127.0.0.1` / `10.30.10.2` | `lab-router` | Simulated Hybrid Router Management API |

> **Security Rule**: The database port (`5434`) and router API (`8099`) must never be bound to public network interfaces.

---

# 3. Python Runtime & Core Library Dependencies

The backend requires **Python 3.12 (x86_64)**. Key pinned dependencies include:

```
fastapi>=0.111.0
uvicorn[standard]>=0.30.0
pydantic>=2.7.0
sqlalchemy>=2.0.30
alembic>=1.13.0
psycopg[binary]>=3.1.18
xgboost>=2.0.3
scikit-learn>=1.5.0
shap>=0.45.0
cryptography==50.0.1
boto3>=1.34.0
google-cloud-compute>=1.18.0
azure-identity>=1.16.0
azure-mgmt-network>=25.3.0
scapy>=2.5.0
pyinstaller>=6.6.0
```

---

# 4. Frontend Technology Stack & Dependencies

The user interface requires **Node.js 18.x or 20.x LTS**:
- **Framework**: React 19.0.0
- **Language**: TypeScript 5.7.0
- **Bundler**: Vite 6.0.0
- **Styling**: Native CSS3 with CSS Custom Properties (Canonical Art-Directed Palette) — Zero Tailwind or bulky UI runtime bloat.
- **Icons & Graphics**: Pure SVG and Unicode icons.

---

# 5. Cloud IAM Permissions Matrix

### 5.1 Amazon Web Services (AWS)
All calls are strictly non-mutating read-only operations:
- `ec2:DescribeVpcs`
- `ec2:DescribeSubnets`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeNetworkInterfaces`
- `ec2:DescribeFlowLogs`
- `logs:FilterLogEvents`
- `logs:GetLogEvents`
- `logs:DescribeLogGroups`
- `s3:GetObject` (if flow logs publish to S3)
- `s3:ListBucket`

### 5.2 Google Cloud Platform (GCP)
- `roles/compute.networkViewer`
- `roles/logging.viewer`

### 5.3 Microsoft Azure
- `Microsoft.Network/virtualNetworks/read`
- `Microsoft.Network/networkSecurityGroups/read`
- `Microsoft.Network/networkSecurityGroups/flowLogs/read`
- `Microsoft.Insights/logs/read`
