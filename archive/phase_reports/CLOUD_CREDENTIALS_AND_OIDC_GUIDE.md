# Cloud Credentials & OIDC Workload Identity Federation Guide

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Scope:** AWS, Google Cloud (Builders Hub), Microsoft Azure, GitHub Actions  

---

## 1. Zero-Trust Security & Secret Elimination

Traditional cloud deployments rely on long-lived static credentials (AWS Access Keys, GCP Service Account JSON keys, Azure Service Principal Client Secrets). These credentials pose severe operational security risks, including credential leaks, lack of non-repudiation, and painful key rotation cycles.

The Security Gateway architecture enforces **Zero Static Secrets** for cloud integrations:
1. **GitHub Actions CI/CD:** Uses OpenID Connect (OIDC) JWT tokens issued by GitHub Actions (`token.actions.githubusercontent.com`).
2. **Gateway Runtime:** Uses native instance metadata, Managed Identities, and Workload Identity token exchanges.
3. **Database Redaction:** The PostgreSQL metadata tables (`cloud_accounts`, `cloud_resources`) strictly exclude secret keys.

---

## 2. GitHub Actions OIDC Authentication Architecture

```
┌─────────────────────┐                 ┌───────────────────────┐
│                     │  1. Request JWT │                       │
│ GitHub Actions Job  ├────────────────►│ GitHub OIDC Provider  │
│                     │◄────────────────┤                       │
└──────────┬──────────┘  2. Return JWT  └───────────────────────┘
           │
           │ 3. Exchange JWT for Temporary Cloud Credentials
           ├────────────────────────┬────────────────────────┐
           ▼                        ▼                        ▼
┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│    AWS STS Token    │  │   GCP WIF Token     │  │  Azure Entra Token  │
│ sts:AssumeRoleWith  │  │ google.iam.workload │  │ api://AzureADToken  │
│    WebIdentity      │  │    IdentityPool     │  │      Exchange       │
└─────────────────────┘  └─────────────────────┘  └─────────────────────┘
```

---

## 3. Provider OIDC Setup Reference

### 3.1 Amazon Web Services (AWS)
- **OIDC Provider URL:** `https://token.actions.githubusercontent.com`
- **Audience:** `sts.amazonaws.com`
- **Subject Claim:** `repo:madhumitag06/hybrid-gateway-security:ref:refs/heads/main`
- **GitHub Workflow Step:**
  ```yaml
  - name: Authenticate to AWS via OIDC
    uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/SecurityGatewayRole
      aws-region: us-east-1
      audience: sts.amazonaws.com
  ```

### 3.2 Google Cloud Platform (Google Builders Hub)
- **Issuer URI:** `https://token.actions.githubusercontent.com`
- **Workload Identity Pool:** `projects/123456789012/locations/global/workloadIdentityPools/hybrid-sec-gh-pool`
- **Provider:** `github-provider`
- **GitHub Workflow Step:**
  ```yaml
  - name: Authenticate to GCP via WIF
    uses: google-github-actions/auth@v2
    with:
      workload_identity_provider: 'projects/123456789012/locations/global/workloadIdentityPools/hybrid-sec-gh-pool/providers/github-provider'
      service_account: 'gateway-sa@gcp-builders-hub-prod.iam.gserviceaccount.com'
  ```

### 3.3 Microsoft Azure
- **Issuer:** `https://token.actions.githubusercontent.com`
- **Audience:** `api://AzureADTokenExchange`
- **Subject:** `repo:madhumitag06/hybrid-gateway-security:ref:refs/heads/main`
- **GitHub Workflow Step:**
  ```yaml
  - name: Authenticate to Azure via OIDC
    uses: azure/login@v2
    with:
      client-id: ${{ secrets.AZURE_CLIENT_ID }}
      tenant-id: ${{ secrets.AZURE_TENANT_ID }}
      subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
  ```

---

## 4. Secret Auditing & Least-Privilege Rules

- **Pre-Commit Checks:** All repository files, workflows, and documentation are scanned to ensure no API keys or passwords are committed.
- **Redaction Middleware:** The `CloudRegistry` automatically purges sensitive keys during database serialization.
- **Audit Logging:** Every token exchange and containment action generates a signed record in `PolicyAuditLogModel`.

