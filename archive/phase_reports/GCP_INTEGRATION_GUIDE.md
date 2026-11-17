# Google Cloud Platform (GCP) Live Integration & WIF Guide

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Provider:** Google Cloud Platform (GCP)  
**Project ID:** `hybrid-gateway-bridge`  
**Project Number:** `77380112089`  
**Region:** `us-central1`  
**Authentication:** Workload Identity Federation (AWS to GCP STS Exchange with Service Account Impersonation)  
**Target Services:** Security Token Service (STS), Cloud IAM, IAM Credentials, Cloud Logging, Cloud Storage, Access Context Manager  

---

## 1. Overview & Architecture

The GCP Cloud Adapter integrates the Security Gateway with Google Cloud environments using **Workload Identity Federation (WIF)**. The security gateway authenticates keylessly by using local AWS SigV4 credentials to request an STS federated token from Google Cloud, which then generates short-lived OAuth2 access tokens via service account impersonation.

### 1.1 Canonical Parameters
| Parameter | Value |
| :--- | :--- |
| **GCP Project ID** | `hybrid-gateway-bridge` |
| **GCP Project Number** | `77380112089` |
| **Primary Region** | `us-central1` |
| **Auth Mode** | `workload_identity` (`external_account`) |
| **Workload Identity Pool** | `hybrid-gateway-pool` |
| **Workload Identity Provider** | `aws-hybrid-gateway` |
| **Impersonated Service Account** | `hybrid-gateway-security@hybrid-gateway-bridge.iam.gserviceaccount.com` |
| **Credentials File** | `C:/Users/LENOVO/.config/hybrid-gateway/gcp-wif-credentials.json` |
| **Credential Vault** | AES-256-GCM encrypted local vault key `gcp_wif_credentials` |
| **Compute Engine API** | Disabled (Billing Account Required) |
| **Compute Resource Ingestion** | 0 Resources (Strictly 0 Fabricated Items) |

---

## 2. Workload Identity Federation (AWS-to-GCP Keyless Authentication)

Google Cloud Workload Identity Federation eliminates the security risk of static, long-lived JSON service account keys.

### 2.1 Cross-Cloud Exchange Mechanism
1. **Local AWS SigV4 Signing**: The gateway uses locally configured AWS credentials (via `boto3` session) to generate a signed AWS STS `GetCallerIdentity` request.
2. **Google STS Token Exchange**: The signed AWS request is transmitted to `https://sts.googleapis.com/v1/token` with audience:
   ```
   //iam.googleapis.com/projects/77380112089/locations/global/workloadIdentityPools/hybrid-gateway-pool/providers/aws-hybrid-gateway
   ```
3. **Federated Token Grant**: Google STS validates the AWS caller identity against the pool provider conditions and returns a federated STS token.
4. **Service Account Impersonation**: The token calls `serviceAccounts.generateAccessToken` to impersonate `hybrid-gateway-security@hybrid-gateway-bridge.iam.gserviceaccount.com`.
5. **Audited API Invocation**: The short-lived bearer token authenticates calls to Cloud Logging, Cloud Storage, and Cloud IAM.

### 2.2 Credentials Configuration Format (`gcp-wif-credentials.json`)
```json
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/77380112089/locations/global/workloadIdentityPools/hybrid-gateway-pool/providers/aws-hybrid-gateway",
  "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "environment_id": "aws1",
    "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
    "regional_cred_verification_url": "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
  },
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/hybrid-gateway-security@hybrid-gateway-bridge.iam.gserviceaccount.com:generateAccessToken"
}
```

---

## 3. Compute Engine API & Billing Transparency

### 3.1 Billing Account Requirement
The `compute.googleapis.com` API requires an active Google Cloud Billing Account linked to project `hybrid-gateway-bridge`. Because a billing account is not currently linked:
- Live VPC networks, subnetworks, and firewall rules cannot be enumerated via Compute API.
- The system reports status `UNAVAILABLE_BILLING_REQUIRED` with transparent remediation instructions.
- **Audit Integrity Guarantee**: The gateway strictly reports 0 compute resources. No synthetic, simulated, or mock VPCs are displayed.

### 3.2 Live API Coverage Matrix
| API / Service | Endpoint | Status | Gateway Capability |
| :--- | :--- | :--- | :--- |
| **Compute Engine API** | `compute.googleapis.com` | `UNAVAILABLE_BILLING_REQUIRED` | VPC, Subnet & Firewall rule discovery (restricted) |
| **IAM Service Account Credentials API** | `iamcredentials.googleapis.com` | `ENABLED_ACCESSIBLE` | Short-lived OAuth2 token generation (`generateAccessToken`) |
| **Security Token Service API** | `sts.googleapis.com` | `ENABLED_ACCESSIBLE` | AWS SigV4 STS token exchange for Workload Identity |
| **Identity and Access Management API** | `iam.googleapis.com` | `ENABLED_ACCESSIBLE` | Service account role inspection & WIF binding validation |
| **Cloud Logging API** | `logging.googleapis.com` | `ENABLED_ACCESSIBLE` | VPC Flow Logs & Admin Activity audit telemetry ingestion |
| **Cloud Storage API** | `storage.googleapis.com` | `ENABLED_ACCESSIBLE` | Flow log archives & forensic PCAP storage |
| **Access Context Manager API** | `accesscontextmanager.googleapis.com` | `ENABLED_ACCESSIBLE` | VPC Service Controls & Zero-Trust perimeter isolation |

**Summary**: 5 of 7 core gateway integration APIs are fully accessible. Compute Engine API discovery will activate automatically as soon as billing is linked.

---

## 4. Telemetry Normalization & Security Operations

Flow records ingested from Google Cloud Logging are normalized into `CanonicalFlowRecord` objects:
- Source and destination IP/port tuples.
- Packet count, byte count, flow duration.
- Derived telemetry features: `conn_rate`, `bytes_per_sec`, `packets_per_sec`, `avg_packet_size`.
- Scored against the authoritative XGBoost V2 model for sub-millisecond anomaly detection.

---

## 5. Troubleshooting & Operations

- **Symptom:** `GCP Probe: DEGRADED (AWS credentials required for SigV4 exchange)`
  - **Resolution:** Ensure AWS credentials are configured in `~/.aws/credentials` (or via `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) so that the local AWS caller identity can be signed for Google STS.
- **Symptom:** `GCP Discovery returns 0 resources`
  - **Resolution:** This is expected when Compute Engine API lacks an active billing account. To enable VPC discovery, attach a billing account in GCP Console > Billing and run `gcloud services enable compute.googleapis.com --project=hybrid-gateway-bridge`.
- **Symptom:** `Google auth module missing`
  - **Resolution:** Installed `google-auth` into the environment (`pip install google-auth`).


