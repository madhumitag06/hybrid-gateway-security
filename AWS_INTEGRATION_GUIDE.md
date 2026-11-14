# AWS Integration Guide & Operations Manual

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Provider:** Amazon Web Services (AWS)  
**Target Services:** VPC, VPC Flow Logs, CloudWatch Logs, IAM, STS, Security Groups, Network ACLs  

---

## 1. Overview & Architecture

The AWS Cloud Adapter connects the Security Gateway to Amazon Virtual Private Clouds (VPCs). It ingests standard Version 2 VPC Flow Logs directly from CloudWatch Logs or Amazon S3, normalizes raw telemetry into the canonical 9-feature ML schema, evaluates threats via authoritative XGBoost V2, and applies dynamic network containment via Security Groups or Network ACLs.

---

## 2. Authentication & Workload Identity Federation

To eliminate static access keys (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`), the gateway supports OpenID Connect (OIDC) identity federation with GitHub Actions and AWS Security Token Service (STS).

### 2.1 IAM OIDC Provider Setup
1. In the AWS Management Console or via Terraform (`infrastructure/modules/identity-federation/`), register the GitHub OIDC provider:
   - **Provider URL:** `https://token.actions.githubusercontent.com`
   - **Audience:** `sts.amazonaws.com`
2. Create an IAM Role (e.g. `arn:aws:iam::123456789012:role/SecurityGatewayRole`) with the following trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:madhumitag06/hybrid-gateway-security:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

### 2.2 Least-Privilege IAM Permission Policy
Attach the following inline policy to grant read-only telemetry inspection and optional containment permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TelemetryReadAccess",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents",
        "logs:GetLogEvents",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeFlowLogs"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ContainmentWriteAccess",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateNetworkAclEntry",
        "ec2:DeleteNetworkAclEntry",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Project": "HybridGateway"
        }
      }
    }
  ]
}
```

---

## 3. VPC Flow Logs Configuration

### 3.1 Enabling VPC Flow Logs (Standard V2 Format)
Create a VPC Flow Log subscription targeting a CloudWatch Log Group:
- **Log Format:** Standard (Version 2)
  `version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status`
- **Traffic Type:** `ALL`
- **Aggregation Interval:** 1 minute (or 10 minutes)
- **Destination:** CloudWatch Logs Group: `/aws/vpc/flow-logs`

---

## 4. Telemetry Ingestion & Parsing

The `AwsTelemetryProvider` parses lines adhering to the V2 format:
- Example Raw Line:
  `2 123456789012 eni-0123456789abcdef0 10.20.10.15 10.20.10.2 44321 443 6 45 38500 1763160000 1763160030 ACCEPT OK`
- Parsed Attributes:
  - Source: `10.20.10.15:44321`
  - Destination: `10.20.10.2:443` (Protocol 6: TCP)
  - Packets: `45`, Bytes: `38,500`, Duration: `30s`
  - Connection Rate: `1.5 conns/sec`, Throughput: `1,283.33 bytes/sec`
  - Canonical 9-Feature vector extracted and evaluated by authoritative XGBoost V2.

---

## 5. Containment Mechanisms

1. **Network ACL Deny Rule:** The gateway dynamically creates high-priority deny rules (e.g. Rule 100) on the target subnet's NACL to block ingress traffic from identified malicious IPs.
2. **Security Group Isolation:** The gateway revokes ingress rules or assigns an isolated quarantine Security Group with zero inbound permissions.
3. **Rollback Plan:** Every containment generates an automated CLI revert command recorded in the audit log:
   `aws ec2 delete-network-acl-entry --network-acl-id acl-sec --rule-number 100 --ingress`

---

## 6. Troubleshooting & Diagnostics

- **Symptom:** `check_connection()` reports `CONFIGURED` instead of `CONNECTED`.
  - **Resolution:** Verify AWS STS credentials or OIDC role ARN in settings. In development mode without AWS credentials, the adapter operates safely in simulated standby.
- **Symptom:** Flow logs skipped during ingestion.
  - **Resolution:** Verify log records do not contain `NODATA` or `SKIPDATA` status flags.

