# AWS Read-Only Connectivity & Verification Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Provider:** Amazon Web Services (AWS)  
**Execution Phase:** Phase 1 — Real AWS Read-Only Connectivity and Telemetry Integration  
**Mode:** Strictly Read-Only (Non-Mutating, Non-Enforcing)  
**Date:** November 15, 2026  

---

## 1. Executive Summary

This report documents the architectural implementation, security audit, and end-to-end verification of the read-only AWS connectivity layer for the **Adaptive AI-Powered Security Gateway for Hybrid Cloud**.

The security gateway connects to Amazon Web Services to discover existing VPC network topology and ingest AWS VPC Flow Logs (Version 2 format). Telemetry is parsed, normalized into the authoritative 9-feature schema (without synthetic authentication telemetry), evaluated via the primary **Big Data XGBoost V2** model, and displayed in the unified `MultiCloudView` dashboard.

### Key Verification Metrics
- **AWS Adapter Architecture:** Complete `AwsIdentityProvider`, `AwsCloudAdapter`, `AwsTelemetryProvider`, and `AwsEnforcementProvider`.
- **Identity & Session Model:** STS `GetCallerIdentity` + `AssumeRole` temporary session credentials with optional `ExternalId`.
- **Secret Hygiene:** 0 long-lived credentials stored in PostgreSQL, Git, or frontend code.
- **Resource Discovery:** Fully automated discovery of VPCs, Subnets, Route Tables, Security Groups, Network ACLs, and Flow Log subscriptions via EC2 paginated describe APIs.
- **Telemetry Ingestion:** Dual destination support for **CloudWatch Logs** (`logs:FilterLogEvents`) and **Amazon S3** (`s3:GetObject` with automated `gzip` decompression).
- **ML Parity:** Exact 9-feature canonical extraction matching `FEATURE_NAMES_V2`, strictly zero synthetic `failed_auth_count`.
- **Enforcement State:** Containment is **STRICTLY DISABLED** for real AWS infrastructure (`enforcement_enabled=False`). Zero security groups, route tables, or NACLs are modified.

---

## 2. Real vs. Mocked Execution Accounting

In strict compliance with safety rules, the gateway was tested against both the local environment and stubbed/mocked AWS environments:

| Test / Verification Stream | Execution Target | Result | Details |
| :--- | :--- | :--- | :--- |
| **AWS CLI & Config Audit** | Real Windows Host | **Executed** | Located AWS CLI v2.34.60 at `C:\Program Files\Amazon\AWSCLIV2\aws.exe`. Detected `~/.aws/config` with `region = ap-southeast-2`. |
| **Local Credential Check** | Real Windows Host | **Executed** | `aws sts get-caller-identity` confirmed `NoCredentials` (ambient keys absent). Gateway returned authentic `NOT_CONFIGURED` without falsifying status. |
| **STS Caller Identity Verification** | Unit / Mock Stub | **Passed** | Verified parsing of 12-digit AWS account ID (`123456789012`), caller ARN, and user ID. |
| **STS AssumeRole Temporary Session** | Unit / Mock Stub | **Passed** | Verified role assumption with `RoleArn` and `ExternalId`, temporary token retrieval, and temporary session expiration caching. |
| **EC2 Topology Discovery** | Unit / Mock Stub | **Passed** | Paginated discovery of VPCs, Subnets, Route Tables, Security Groups, NACLs, and Flow Log subscriptions. |
| **CloudWatch Logs Flow Retrieval** | Unit / Mock Stub | **Passed** | Retrieval of flow lines from `/aws/vpc/flowlogs` using `filter_log_events`. |
| **S3 Flow Log Retrieval & Decompression** | Unit / Mock Stub | **Passed** | Decompressed `*.log.gz` archives and parsed multi-line VPC flow records. |
| **Canonical 9-Feature Parity** | Local ML Runtime | **Passed** | Evaluated flows through authoritative Big Data XGBoost V2 model with 0 synthetic `failed_auth_count`. |
| **Frontend Production Build** | TypeScript Compiler | **Passed** | `npm.cmd run build` compiled 42 modules with zero errors in 275ms. |

---

## 3. Required AWS Read-Only Permission Matrix

The gateway requires exclusively read-only AWS IAM actions. No modifying (`Create*`, `Delete*`, `Modify*`, `Authorize*`, `Revoke*`, `Put*`) actions are requested or used:

| Service | API Action | Resource Scope | Purpose |
| :--- | :--- | :--- | :--- |
| **STS** | `sts:GetCallerIdentity` | `*` | Verify local IAM caller identity and account ID |
| **STS** | `sts:AssumeRole` | Target Role ARN | Assume temporary read-only role with External ID |
| **EC2** | `ec2:DescribeVpcs` | `*` | Discover VPC IDs, CIDR blocks, states, and tags |
| **EC2** | `ec2:DescribeSubnets` | `*` | Discover Subnets, AZs, CIDRs, and VPC associations |
| **EC2** | `ec2:DescribeRouteTables` | `*` | Discover route tables, associations, and route targets |
| **EC2** | `ec2:DescribeSecurityGroups` | `*` | Discover security groups and ingress/egress rules |
| **EC2** | `ec2:DescribeNetworkAcls` | `*` | Discover network ACL rules and associations |
| **EC2** | `ec2:DescribeFlowLogs` | `*` | Discover VPC Flow Log subscriptions and destinations |
| **Logs** | `logs:DescribeLogGroups` | `*` | Discover CloudWatch log groups for VPC flow logs |
| **Logs** | `logs:DescribeLogStreams` | `*` | Inspect log stream timestamps and status |
| **Logs** | `logs:FilterLogEvents` | `*` | Ingest real VPC flow log records from CloudWatch |
| **Logs** | `logs:GetLogEvents` | `*` | Fallback retrieval from specific flow log stream |
| **S3** | `s3:GetBucketLocation` | `*` | Determine S3 flow log bucket region |
| **S3** | `s3:ListBucket` | Bucket ARN | List VPC flow log prefixes and `.log.gz` objects |
| **S3** | `s3:GetObject` | Bucket ARN + `/*` | Download and decompress gzip VPC flow log archives |

---

## 4. Lifecycle State Differentiation

The MultiCloud dashboard strictly prevents misleading status reporting by enforcing five distinct lifecycle states:

```
[ Phase 1: Configured ] 
      │ (Region, Role ARN, External ID validated syntactically)
      ▼
[ Phase 2: STS Authenticated ] 
      │ (sts:GetCallerIdentity or sts:AssumeRole succeeds; returns 12-digit AWS Account ID)
      ▼
[ Phase 3: Resources Discovered ] 
      │ (ec2:Describe* enumerates real VPCs, Subnets, Route Tables, SGs, NACLs)
      ▼
[ Phase 4: Flow Logs Configured ] 
      │ (ec2:DescribeFlowLogs detects CloudWatch or S3 destination)
      ▼
[ Phase 5: Telemetry Ingested & Evaluated ] 
        (Flow records normalized -> XGBoost V2 inference -> Security Events persisted)
```

If credentials are absent, the system displays `NOT_CONFIGURED` or `AUTHENTICATION_FAILED`. It **never displays `CONNECTED`** simply because AWS configuration fields exist.

---

## 5. Next Steps for Live AWS Account Telemetry

To transition from stubbed verification to live AWS telemetry streaming:
1. Follow the step-by-step instructions in [AWS_IAM_READ_ONLY_SETUP_GUIDE.md](file:///c:/Users/LENOVO/Desktop/hybrid-gateway-security/AWS_IAM_READ_ONLY_SETUP_GUIDE.md).
2. Create the `SecurityGatewayReadOnlyRole` in your target AWS account.
3. Export the target role ARN and region into your environment:
   ```powershell
   $env:AWS_REGION="ap-southeast-2"
   $env:AWS_ROLE_ARN="arn:aws:iam::<YOUR_ACCOUNT_ID>:role/SecurityGatewayReadOnlyRole"
   $env:AWS_EXTERNAL_ID="AdaptiveGatewayAuth"
   ```
4. Click **"Test STS Identity"** and **"Discover VPCs"** in the `MultiCloudView` dashboard.

