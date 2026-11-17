# Adaptive AI-Powered Security Gateway for Hybrid Cloud
## Authoritative Setup, Deployment & Configuration Guide

**Version:** 1.0.0 (Production Release Candidate)  
**Target Operating Systems:** Windows 10/11 x64, Linux (Ubuntu 22.04+ / Debian 12)  
**Target Environments:** Local Workstation, Docker Hybrid Lab, Standalone Windows Executable  

---

# 1. System Requirements & Prerequisites

### 1.1 Software Requirements
| Component | Minimum Version | Recommended Version | Purpose |
|---|---|---|---|
| **Python** | 3.11 | 3.12.x x64 | Backend FastAPI runtime & ML inference |
| **Node.js** | 18.x LTS | 20.x or 22.x LTS | Frontend React development & asset build |
| **Docker Desktop** | 24.x | 26.x or newer | Multi-container hybrid cloud lab |
| **PostgreSQL** | 15.x | 16.3 | Relational database (or embedded SQLite) |
| **Git** | 2.40+ | Latest | Version control |

### 1.2 Hardware Sizing
- **CPU**: 4 physical cores minimum (8 cores recommended for concurrent ML inference).
- **RAM**: 8 GB minimum (16 GB recommended when running full Docker lab).
- **Disk Storage**: 10 GB free space on OS drive (for Docker images and PCAP storage).

---

# 2. Environment Configuration (`.env`)

A comprehensive `.env.example` template is provided in the repository root. Before launching, copy this file to `.env`:

```bash
cp .env.example .env
```

### 2.1 Post-Implementation Cloud Credential Configuration
As instructed by the master directive, the application is fully implemented and sealed. You can add your live cloud credentials to `.env` whenever you are ready:

```ini
# ==============================================================================
# CLOUD CREDENTIAL VAULT MASTER KEY (AES-256-GCM)
# Generate a 32-byte hex key using: python -c "import secrets; print(secrets.token_hex(32))"
# ==============================================================================
CLOUD_CREDENTIAL_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
CLOUD_CREDENTIAL_KEY_VERSION=1

# ==============================================================================
# AMAZON WEB SERVICES (AWS) CONFIGURATION
# ==============================================================================
# Authentication Mode: "IAM_ROLE" (recommended for STS AssumeRole) or "ACCESS_KEYS"
AWS_AUTH_MODE=IAM_ROLE
AWS_ACCOUNT_ID=698766075180
AWS_DEFAULT_REGION=ap-southeast-2
AWS_ROLE_ARN=arn:aws:iam::698766075180:role/SecurityGatewayReadOnlyRole
AWS_EXTERNAL_ID=hybrid-gateway-sec-session
AWS_VPC_FLOW_LOG_GROUP=/aws/vpc/flow-logs-production
AWS_VPC_FLOW_S3_BUCKET=
# Optional Access Keys (if AWS_AUTH_MODE=ACCESS_KEYS):
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# ==============================================================================
# GOOGLE CLOUD PLATFORM (GCP) CONFIGURATION
# ==============================================================================
# Authentication Mode: "SERVICE_ACCOUNT_KEY" or "BUILDERS_HUB"
GCP_AUTH_MODE=BUILDERS_HUB
GCP_PROJECT_ID=builders-hub-prod
GCP_REGION=asia-southeast1
GCP_SERVICE_ACCOUNT_EMAIL=security-gateway@builders-hub-prod.iam.gserviceaccount.com
# Path to service account key file (or leave empty if using application default):
GCP_SERVICE_ACCOUNT_KEY_FILE=

# ==============================================================================
# MICROSOFT AZURE CONFIGURATION
# ==============================================================================
# Authentication Mode: "CLIENT_SECRET" or "FEDERATED_OIDC"
AZURE_AUTH_MODE=CLIENT_SECRET
AZURE_TENANT_ID=72f988bf-86f1-41af-91ab-2d7cd011db47
AZURE_SUBSCRIPTION_ID=sub-azure-enterprise
AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_SECRET=
AZURE_DEFAULT_REGION=eastus
```

> **Security Note**: Never commit `.env` containing live secrets to Git. The `.gitignore` is pre-configured to strictly exclude `.env`.

---

# 3. Deployment Modes

### Mode A: Full Docker Compose Hybrid Lab (Recommended)
This spins up the complete microservice mesh:
- `gateway-api` (FastAPI backend on port 8000)
- `frontend` (Vite / Nginx on port 5175)
- `traffic-generator` (Attack simulation daemon)
- `telemetry-sensor` (Packet capture sensor)
- `lab-router` (Simulated hybrid interconnect router on port 8099)
- `postgres` (PostgreSQL database on port 5434)

```bash
docker compose up --build -d
```
Access the application at: **`http://localhost:5175`**

### Mode B: Local Workstation Development (Lightweight)
Run backend and frontend independently for development and testing.

**1. Backend:**
```bash
cd backend
python -m venv venv
venv\Scripts\activate          # On Windows
# source venv/bin/activate     # On Linux / macOS
pip install -r requirements.txt
alembic upgrade head
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**2. Frontend:**
```bash
npm install
npm run dev
```
Access the frontend at: **`http://localhost:5173`**

### Mode C: Standalone Native Windows Executable
A single bundled executable is pre-packaged for zero-dependency execution on Windows:

1. Locate `AdaptiveSecurityGateway.exe` in the project root.
2. Double-click or execute from PowerShell:
   ```powershell
   .\AdaptiveSecurityGateway.exe
   ```
3. The executable initializes the embedded SQLite database, mounts static assets, and launches the gateway on port 8000.

---

# 4. Cloud Provider Least-Privilege Setup

### 4.1 AWS IAM Least-Privilege Configuration
1. In the target AWS account, create an IAM Role named `SecurityGatewayReadOnlyRole`.
2. Attach the Trust Relationship:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": { "AWS": "arn:aws:iam::GATEWAY_ACCOUNT_ID:root" },
         "Action": "sts:AssumeRole",
         "Condition": { "StringEquals": { "sts:ExternalId": "hybrid-gateway-sec-session" } }
       }
     ]
   }
   ```
3. Attach the Permissions Policy (`AmazonEC2ReadOnlyAccess` and `CloudWatchLogsReadOnlyAccess`):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "ec2:DescribeVpcs",
           "ec2:DescribeSubnets",
           "ec2:DescribeSecurityGroups",
           "ec2:DescribeFlowLogs",
           "logs:FilterLogEvents",
           "logs:GetLogEvents"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

### 4.2 GCP Service Account Configuration
1. In Google Cloud Console, navigate to **IAM & Admin** $\to$ **Service Accounts**.
2. Create a service account: `security-gateway@YOUR_PROJECT.iam.gserviceaccount.com`.
3. Grant the role **Compute Network Viewer** (`roles/compute.networkViewer`).
4. Generate a JSON Key and upload via the UI Onboarding Wizard or place at the path in `GCP_SERVICE_ACCOUNT_KEY_FILE`.

### 4.3 Microsoft Azure App Registration
1. In the Microsoft Entra ID portal, register a new application: `Adaptive-Security-Gateway`.
2. Generate a Client Secret under **Certificates & secrets**.
3. Under your Subscription's **Access Control (IAM)**, assign the **Reader** role to the application.
4. Input the `tenant_id`, `client_id`, and `client_secret` via the UI Onboarding Wizard.

---

# 5. Verification & Health Check

After launching, verify the platform status:
- Gateway API Health: `GET http://localhost:8000/api/v1/health`
- Multi-Cloud Health: `GET http://localhost:8000/api/v1/cloud/health`
- Frontend Dashboard: Navigate to `http://localhost:5175` (or `5173`) and observe:
  - System Operational indicator (green pulse).
  - 5 Collapsible navigation groups in the left sidebar.
  - Multi-Cloud view sub-tabs (Overview, Accounts, AWS, GCP, Azure, Inventory, Telemetry).
