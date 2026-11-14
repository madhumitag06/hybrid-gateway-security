# Enterprise CI/CD Pipeline Guide & Workflow Specifications

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Engine:** GitHub Actions  
**Workflows:** `ci.yml`, `security-scan.yml`, `docker-build.yml`, `infrastructure-validate.yml`, `windows-exe-build.yml`, `release.yml`  

---

## 1. Pipeline Matrix Overview

The continuous integration and deployment architecture provides automated validation across testing, security, container packaging, infrastructure-as-code, and native Windows executable distribution.

| Workflow File | Trigger Events | Purpose | Execution Environment |
| :--- | :--- | :--- | :--- |
| `ci.yml` | Push & PR to `main`, `develop` | Pytest backend suite, TypeScript check, Vite build | `ubuntu-latest` |
| `security-scan.yml` | Push to `main`, Weekly cron | Bandit Python AST scan, pip-audit dependencies | `ubuntu-latest` |
| `docker-build.yml` | Push to `main`, tag `v*` | Multi-stage image build, non-root user verification | `ubuntu-latest` |
| `infrastructure-validate.yml` | Push/PR in `infrastructure/**` | Terraform fmt, module init, and syntax validate | `ubuntu-latest` |
| `windows-exe-build.yml` | Tag `v*`, Manual dispatch | PyInstaller build, XGBoost native DLL bundle | `windows-latest` |
| `release.yml` | Tag `v*` | Draft GitHub semantic release with changelog | `ubuntu-latest` |

---

## 2. Workflow Specifications

### 2.1 Continuous Integration (`ci.yml`)
- **Backend Job:** Installs Python 3.11, preloads requirements, executes full pytest suite with 100% pass criteria:
  - `test_cloud_abstraction.py`
  - `test_aws_adapter.py`
  - `test_gcp_adapter.py`
  - `test_azure_adapter.py`
  - `test_telemetry_normalization.py`
  - `test_cloud_registry.py`
- **Frontend Job:** Sets up Node.js 20, runs `npm ci`, and executes `npm run build` (`tsc -b && vite build`) to guarantee clean TypeScript compilation and asset bundling.

### 2.2 Security Scanning (`security-scan.yml`)
- Runs Bandit on `backend/app/` to catch injection vulnerabilities, hardcoded passwords, or unsafe subprocess calls.
- Executes `pip-audit` against `backend/requirements.txt` to identify vulnerable dependencies in the supply chain.

### 2.3 Standalone Windows Executable Build (`windows-exe-build.yml`)
- Executes on GitHub Actions `windows-latest` runners.
- Builds the Vite production distribution (`dist/`).
- Invokes PyInstaller with `gateway.spec`.
- Verifies that `xgboost.dll` is bundled correctly into `dist/` or `_internal/`.
- Uploads the signed standalone executable artifact for release distribution.

---

## 3. GitHub Secrets & Variables Configuration

When setting up repository secrets in GitHub:
- **`AWS_ROLE_ARN`**: IAM Role ARN for OIDC assume-role.
- **`GCP_WORKLOAD_IDENTITY_PROVIDER`**: WIF provider path.
- **`GCP_SERVICE_ACCOUNT`**: Service account email.
- **`AZURE_CLIENT_ID`**: Entra ID Application Client ID.
- **`AZURE_TENANT_ID`**: Entra ID Directory Tenant ID.
- **`AZURE_SUBSCRIPTION_ID`**: Azure Subscription ID.
- **CRITICAL NOTE:** Zero static passwords or long-lived secret keys are required.

