# AWS VPC FLOW LOGS — LEAST-PRIVILEGE IAM PERMISSION PROPOSAL
## Least-Privilege IAM Policy for Real AWS VPC Flow Logs Ingestion & Inventory Discovery

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Target AWS Account ID:** `698766075180`  
**Region:** `ap-southeast-2` (Sydney)  
**Target IAM Role:** `SecurityGatewayReadOnlyRole`  
**Role ARN:** `arn:aws:iam::698766075180:role/SecurityGatewayReadOnlyRole`  
**External ID:** `AdaptiveGatewayAuth`  
**Status:** **PROPOSAL FOR USER REVIEW (DO NOT APPLY AUTOMATICALLY)**  

---

## 1. Executive Summary

In compliance with the project safety charter, **no IAM policies have been modified in your AWS account**.

This document outlines the exact least-privilege permissions required to enable live VPC Flow Logs ingestion (via CloudWatch Logs or Amazon S3) and addresses the Phase 1 permission boundary finding regarding Internet Gateway discovery.

You can review this policy and manually attach it to the `SecurityGatewayReadOnlyRole` in your AWS Console when you are ready to activate live Flow Logs.

---

## 2. Review of Phase 1 Permission Finding

### The `ec2:DescribeInternetGateways` Observation
During Phase 1 network topology discovery, invoking `ec2:DescribeInternetGateways` returned an AWS `UnauthorizedOperation` error.

- **Impact Analysis:**
  The current IAM policy permits `ec2:DescribeRouteTables`. Because internet-facing route tables in AWS reference attached Internet Gateways (e.g. `igw-00159811a9c4fdfdd` via `0.0.0.0/0` next-hop route), the gateway's adapter was engineered with a graceful fallback that automatically extracts referenced gateway IDs without needing direct `ec2:DescribeInternetGateways` permissions.
- **Recommendation:**
  Adding `ec2:DescribeInternetGateways` and `ec2:DescribeNatGateways` is **optional but recommended** if you want the gateway to directly enumerate detached gateways or read tags directly from gateway objects rather than relying solely on route table associations.

---

## 3. Required Least-Privilege Actions Breakdown

### 3.1 Network Inventory Discovery (EC2)
| Action | Purpose | Mandatory? |
| :--- | :--- | :--- |
| `ec2:DescribeVpcs` | Discovers VPC CIDR blocks and tenancy | **Yes** |
| `ec2:DescribeSubnets` | Discovers subnets, CIDRs, and availability zones | **Yes** |
| `ec2:DescribeRouteTables` | Discovers route associations and next-hops | **Yes** |
| `ec2:DescribeSecurityGroups` | Discovers active security group firewall rules | **Yes** |
| `ec2:DescribeNetworkAcls` | Discovers subnet network access control lists | **Yes** |
| `ec2:DescribeFlowLogs` | Queries active VPC Flow Log subscriptions | **Yes** |
| `ec2:DescribeInternetGateways` | Direct discovery of internet gateways and tags | *Recommended* |
| `ec2:DescribeNatGateways` | Direct discovery of NAT gateways and public IPs | *Recommended* |

### 3.2 CloudWatch Logs Ingestion
| Action | Purpose | Mandatory? |
| :--- | :--- | :--- |
| `logs:DescribeLogGroups` | Enumerates configured CloudWatch log groups | **Yes** (if using CW) |
| `logs:DescribeLogStreams` | Discovers ENI log streams within log group | **Yes** (if using CW) |
| `logs:FilterLogEvents` | Streams log events across streams with time windowing | **Yes** (if using CW) |
| `logs:GetLogEvents` | Point-in-time event retrieval from specific stream | **Yes** (if using CW) |

### 3.3 Amazon S3 Ingestion (Optional Alternative to CloudWatch)
| Action | Purpose | Mandatory? |
| :--- | :--- | :--- |
| `s3:ListBucket` | Enumerates `.log.gz` objects under `AWSLogs/` prefix | **Yes** (if using S3) |
| `s3:GetObject` | Reads compressed `.log.gz` flow records for gunzip | **Yes** (if using S3) |
| `s3:GetBucketLocation` | Confirms bucket region (`ap-southeast-2`) | **Yes** (if using S3) |

---

## 4. Proposed Consolidated IAM Policy

You can create or update an inline policy on `SecurityGatewayReadOnlyRole` in account `698766075180`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Ec2NetworkTopologyReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchFlowLogsReadOnly",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents",
        "logs:GetLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:ap-southeast-2:698766075180:log-group:*",
        "arn:aws:logs:ap-southeast-2:698766075180:log-group:*:log-stream:*"
      ]
    },
    {
      "Sid": "S3FlowLogsReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::*-vpc-flowlogs-*"
    },
    {
      "Sid": "S3FlowLogsObjectRead",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::*-vpc-flowlogs-*/*"
    }
  ]
}
```

---

## 5. IAM Trust Policy Verification

The existing trust policy on `SecurityGatewayReadOnlyRole` must continue to enforce the `AdaptiveGatewayAuth` external ID:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeRoleWithExternalId",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::698766075180:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "AdaptiveGatewayAuth"
        }
      }
    }
  ]
}
```

---

## 6. Manual Setup Steps to Enable Real AWS VPC Flow Logs

When you are ready to stream live AWS traffic through the security gateway, follow these steps in the AWS Console:

### Step 1: Create a CloudWatch Log Group
1. Open the **Amazon CloudWatch** console in `ap-southeast-2`.
2. Navigate to **Logs** → **Log groups**.
3. Click **Create log group**.
4. Set **Log group name** to: `/aws/vpc/flowlogs/ap-southeast-2-default`.
5. Set **Retention setting** (e.g. 7 days or 14 days).

### Step 2: Create Flow Logs Publishing IAM Role
1. Open the **AWS IAM** console.
2. Create a service role for VPC Flow Logs:
   - **Trusted entity:** `vpc-flow-logs.amazonaws.com`
   - **Policy:**
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Action": [
             "logs:CreateLogGroup",
             "logs:CreateLogStream",
             "logs:PutLogEvents",
             "logs:DescribeLogGroups",
             "logs:DescribeLogStreams"
           ],
           "Effect": "Allow",
           "Resource": "*"
         }
       ]
     }
     ```
   - **Role name:** `VpcFlowLogsPublisherRole`.

### Step 3: Enable Flow Logs on Your VPC
1. Open the **Amazon VPC** console in `ap-southeast-2`.
2. Select your VPC (`vpc-0fc9db63fecb34fad`).
3. Click the **Flow logs** tab → **Create flow log**.
4. Set:
   - **Filter:** `All` (or `Reject` if you only want rejected traffic).
   - **Maximum aggregation interval:** `1 minute` (for real-time streaming).
   - **Destination:** `Send to CloudWatch Logs`.
   - **Destination log group:** `/aws/vpc/flowlogs/ap-southeast-2-default`.
   - **IAM role:** Select `VpcFlowLogsPublisherRole`.
   - **Log record format:** `AWS default format` (Version 2).
5. Click **Create flow log**.

### Step 4: Verify in Security Gateway Dashboard
1. Open the Security Gateway SecOps dashboard.
2. Navigate to **Multi-Cloud Architecture**.
3. Click **Refresh** or **Inspect Flow Logs**.
4. The dashboard will now reflect `1 Active Subscription` and allow streaming live logs via **⚡ Poll Live AWS Logs**.

