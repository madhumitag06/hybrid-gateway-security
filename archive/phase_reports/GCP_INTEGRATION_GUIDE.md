# Google Cloud Platform (Google Builders Hub) Integration Guide

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Provider:** Google Cloud Platform (GCP) / Google Builders Hub  
**Target Services:** VPC Networks, Cloud Logging VPC Flow Logs, Workload Identity Federation, Cloud Firewalls  

---

## 1. Overview & Architecture

The GCP Cloud Adapter integrates the Security Gateway with Google Cloud environments, specifically designed for development and deployment via Google Builders Hub. It captures VPC Flow Logs from Cloud Logging, extracts canonical 9-feature vectors, runs inference against authoritative XGBoost V2, and applies dynamic ingress deny firewall rules.

---

## 2. Workload Identity Federation (Keyless Authentication)

Google Cloud Workload Identity Federation allows GitHub Actions and the Security Gateway to authenticate without managing or exporting static JSON service account keys.

### 2.1 Workload Identity Pool Setup
1. Create a Workload Identity Pool in your GCP project (e.g., `gcp-builders-hub-prod`):
   ```bash
   gcloud iam workload-identity-pools create "hybrid-sec-gh-pool" \
     --project="gcp-builders-hub-prod" \
     --location="global" \
     --display-name="GitHub Actions Pool"
   ```
2. Create an OIDC Provider within the pool:
   ```bash
   gcloud iam workload-identity-pools providers create-oidc "github-provider" \
     --project="gcp-builders-hub-prod" \
     --location="global" \
     --workload-identity-pool="hybrid-sec-gh-pool" \
     --display-name="GitHub Provider" \
     --issuer-uri="https://token.actions.githubusercontent.com" \
     --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository"
   ```
3. Grant the repository permissions to impersonate the deployer service account:
   ```bash
   gcloud iam service-accounts add-iam-policy-binding "gateway-sa@gcp-builders-hub-prod.iam.gserviceaccount.com" \
     --project="gcp-builders-hub-prod" \
     --role="roles/iam.workloadIdentityUser" \
     --member="principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/hybrid-sec-gh-pool/attribute.repository/madhumitag06/hybrid-gateway-security"
   ```

---

## 3. GCP VPC Flow Logs Configuration

### 3.1 Enabling Flow Logs on Subnetworks
In your custom VPC, enable flow logs with 5-second aggregation intervals and complete metadata:
```bash
gcloud compute networks subnets update hybrid-gcp-subnet-uscentral1 \
  --region=us-central1 \
  --project=gcp-builders-hub-prod \
  --enable-flow-logs \
  --logging-flow-sampling=0.5 \
  --logging-aggregation-interval=INTERVAL_5_SEC \
  --logging-metadata=INCLUDE_ALL_METADATA
```

### 3.2 Cloud Logging Flow Log JSON Schema
Flow logs are written to Cloud Logging under the resource type `gce_subnetwork`:
```json
{
  "insertId": "gcp-rec-101",
  "jsonPayload": {
    "connection": {
      "src_ip": "10.40.10.15",
      "dest_ip": "10.40.10.2",
      "src_port": 49152,
      "dest_port": 443,
      "protocol": 6
    },
    "bytes_sent": "25000",
    "packets_sent": "30",
    "start_time": "2026-11-15T00:10:00Z",
    "end_time": "2026-11-15T00:10:15Z",
    "rule_details": {
      "action": "ALLOW"
    }
  },
  "resource": {
    "type": "gce_subnetwork",
    "labels": {
      "subnetwork_name": "hybrid-gcp-subnet-uscentral1"
    }
  }
}
```

---

## 4. Telemetry Normalization & Parity

The `GcpTelemetryProvider` maps the Cloud Logging JSON schema into `CanonicalFlowRecord`:
- Extracts: `packet_count` (from `packets_sent`), `byte_count` (from `bytes_sent`), `duration` (from `start_time` and `end_time`).
- Computes: `conn_rate`, `bytes_per_sec`, `packets_per_sec`, `avg_packet_size`.
- Evaluates: Passes normalized 9-feature vector to XGBoost V2 for instant threat scoring.
- Authentication failures: Strictly excluded. `failed_auth_count` is NEVER synthesized.

---

## 5. Containment via Google Cloud Firewalls

When high-risk anomalous behavior (e.g. port scan, volumetric burst, brute-force probe) is confirmed, the gateway executes containment:
- **Action:** Creates a priority-100 deny rule in the VPC network:
  ```bash
  gcloud compute firewall-rules create "fw-deny-target-ip" \
    --project=gcp-builders-hub-prod \
    --network=hybrid-gcp-vpc \
    --priority=100 \
    --direction=INGRESS \
    --action=DENY \
    --rules=all \
    --source-ranges=198.51.100.99/32
  ```
- **Reversion:** The audit record retains the revert command:
  `gcloud compute firewall-rules delete fw-deny-target-ip --project gcp-builders-hub-prod --quiet`

---

## 6. Troubleshooting

- **Symptom:** `GCP Workload Identity Token Exchange Fails`
  - **Resolution:** Verify that `gcp_workload_identity_provider` in configuration matches the format `projects/{PROJECT_NUMBER}/locations/global/workloadIdentityPools/{POOL}/providers/{PROVIDER}`.
- **Symptom:** Flow logs not received from Cloud Logging.
  - **Resolution:** Verify VPC subnet flow logs are enabled and the filter string matches `logName:"logs/compute.googleapis.com%2Fvpc_flows"`.

