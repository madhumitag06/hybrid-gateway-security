# Adaptive AI-Powered Security Gateway for Hybrid Cloud
## Enterprise-Grade Threat Classification, Explainable AI & Multi-Cloud Security Governance

[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19.0.0-61DAFB.svg?style=flat&logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7.0-3178C6.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)
[![XGBoost](https://img.shields.io/badge/XGBoost-V2_Canonical-FF6600.svg?style=flat)](https://xgboost.readthedocs.io)
[![Python](https://img.shields.io/badge/Python-3.12_x64-3776AB.svg?style=flat&logo=python)](https://python.org)
[![AES-256-GCM](https://img.shields.io/badge/Vault-AES--256--GCM-green.svg?style=flat)](./SECURITY.md)

An intelligent, multi-layer security gateway and telemetry orchestration platform engineered for distributed hybrid cloud infrastructure: on-premises enterprise networks, Docker container meshes, Amazon Web Services (AWS), Google Cloud Platform (GCP Builders Hub), and Microsoft Azure.

---

## 🏛️ Key System Highlights

- **Multi-Cloud Defense Matrix**: Unified monitoring, resource discovery, and zero-trust telemetry normalization across AWS VPC Flow Logs, GCP VPC Flow Logs, Azure NSG Flow Events, and local Docker workloads.
- **XGBoost V2 Canonical Inference**: 9-feature physical invariant pipeline achieving real-time multiclass classification of reconnaissance sweeps, volumetric bursts, credential brute force, and data exfiltration.
- **Explainable AI (XAI)**: Exact local feature attribution powered by `shap.TreeExplainer`, delivering waterfall visualizations and plain-English threat rationale for every high-risk alert.
- **AES-256-GCM Envelope Credential Vault**: Hardened client-side / at-rest envelope encryption securing cloud credentials and API secrets in PostgreSQL (Alembic Revision `005`).
- **Graduated Containment Engine**: Time-to-Live (TTL) automated quarantine lifecycle supporting `DRY_RUN`, `SANDBOX`, and `LIVE` enforcement modes.
- **5-Group Collapsible Navigation & 7 Multi-Cloud Sub-Tabs**: Modern cybersecurity console with canonical palette, micro-elevations, and responsive routing.

---

## 📚 Core Authoritative Documentation

| Document | Description |
|---|---|
| [RUN_PROJECT.md](./RUN_PROJECT.md) | **Beginner-Friendly Copy-Paste Run Guide**: Step-by-step instructions for running the standalone EXE, dev mode, or Docker. |
| [PROJECT_DOCUMENTATION.md](./PROJECT_DOCUMENTATION.md) | Comprehensive architecture reference, model schemas, SHAP explainability, and multi-cloud mechanics. |
| [SETUP_GUIDE.md](./SETUP_GUIDE.md) | Step-by-step workstation setup, Docker deployment, and cloud credential configuration instructions. |
| [REQUIREMENTS.md](./REQUIREMENTS.md) | Formal hardware, operating system, port allocation, and cloud IAM permission requirements. |
| [SECURITY.md](./SECURITY.md) | NIST/OWASP security architecture, AES-256-GCM vault, RBAC matrix, and threat modeling (STRIDE). |
| [FINAL_IMPLEMENTATION_AND_ACCEPTANCE_REPORT.md](./FINAL_IMPLEMENTATION_AND_ACCEPTANCE_REPORT.md) | Detailed engineering log, modified files manifest, dynamic visualizations, and manual acceptance checklist. |

---

## 🚀 Quick Start Deployment

For complete, copy-paste instructions across all options, see [RUN_PROJECT.md](./RUN_PROJECT.md).

### Option 1: Standalone Windows Executable (Recommended)
1. Start PostgreSQL: `docker compose up -d db`
2. Run the executable from PowerShell:
   ```powershell
   .\dist\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe
   ```
   *(Or double-click `AdaptiveSecurityGateway.exe` in `dist\AdaptiveSecurityGateway\`)*
3. Access the dashboard at: **`http://localhost:8000`**

### Option 2: Docker Hybrid Lab
```bash
# In deployment/hybrid-lab
cd deployment/hybrid-lab
docker compose up -d
```
Access the console at: **`http://localhost:5175`** (Gateway API on `http://localhost:8001`)

### Option 3: Local Workstation Development
```powershell
# Backend (Terminal 1)
.\ml\.venv\Scripts\Activate.ps1
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

# Frontend (Terminal 2)
cmd /c "npm run dev"
```
Access the console at: **`http://localhost:5174`**

---

## 🔒 Cloud Credential Policy & Onboarding

Cloud credentials can be onboarded via two seamless methods:
1. **Interactive UI Wizard**: Navigate to **Multi-Cloud $\to$ Cloud Accounts** and click **"+ Add Account"**. Enter your credentials with AES-256-GCM vault envelope sealing.
2. **Environment File (`.env`)**: Add your AWS, GCP, or Azure keys directly into `.env` following the instructions in [SETUP_GUIDE.md](./SETUP_GUIDE.md).

---

## 📦 Directory Structure

```
.
├── backend/                  # FastAPI 0.111 application
│   ├── alembic/              # Database migration revisions (001 through 005)
│   ├── app/
│   │   ├── api/v1/           # REST endpoints (auth, cloud, ml, events, telemetry)
│   │   ├── cloud/            # Multi-cloud adapters, vault, and services
│   │   ├── ml/               # XGBoost V2 model artifacts & SHAP explainer
│   │   ├── models/           # SQLAlchemy 2.0 ORM schemas
│   │   └── services/         # Containment, flow aggregation & sensor bridge
│   └── requirements.txt      # Pinned Python dependencies
├── src/                      # React 19 + TypeScript frontend
│   ├── components/           # UI views (MultiCloud, Analytics, Simulation, etc.)
│   ├── services/             # Typed API clients (cloud, dashboard, auth, predictor)
│   ├── App.tsx               # Primary layout with 5 collapsible nav groups
│   └── App.css               # Canonical art-directed styling & micro-elevations
├── archive/                  # Historical artifacts and phase reports
│   └── phase_reports/        # Consolidated historical markdown reports
├── .env.example              # Canonical environment template
├── AdaptiveSecurityGateway.exe # Standalone Windows executable
├── PROJECT_DOCUMENTATION.md  # Comprehensive architecture reference
├── SETUP_GUIDE.md            # Setup and cloud credential guide
├── REQUIREMENTS.md           # Formal system & port specifications
└── SECURITY.md               # Cryptographic and security policy
```

---

## 🛡️ License & Academic Notice
Developed for advanced hybrid-cloud cybersecurity research. Distributed under the MIT License.
