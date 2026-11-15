# AWS IAM Read-Only Setup Guide & Operations Manual

**Target Role Name:** `SecurityGatewayReadOnlyRole`  
**Purpose:** Grants the Adaptive AI-Powered Security Gateway strictly read-only access to discover VPC network topology and ingest VPC Flow Logs.  
**Security Guarantee:** Zero mutating permissions. Cannot create, modify, or delete any AWS resources. Cannot modify Security Groups, NACLs, or Route Tables.

---

## 1. Architecture: Temporary Credentials via STS AssumeRole

```
┌──────────────────────────────────────┐
│ Local Security Gateway               │
│ - Reads AWS_ROLE_ARN                 │
│ - Reads AWS_EXTERNAL_ID              │
└──────────────────┬───────────────────┘
                   │ 1. sts:AssumeRole
                   ▼
┌──────────────────────────────────────┐
│ AWS Security Token Service (STS)     │
│ - Validates Trust Policy & ExternalID│
│ - Issues temporary 1-hour credentials│
└──────────────────┬───────────────────┘
                   │ 2. Temporary Session
                   ▼
┌────────────────────────────────────────────────────────┐
│ Target AWS Account                                     │
│ ├── ec2:Describe*   (VPCs, Subnets, SGs, NACLs)       │
│ ├── logs:Filter*    (CloudWatch VPC Flow Logs)         │
│ └── s3:GetObject    (S3 VPC Flow Log .log.gz archives) │
└────────────────────────────────────────────────────────┘
```

---

## 2. Step 1: Create the IAM Role Trust Policy

The trust policy specifies who is allowed to assume the role. If you are assuming this role from your local IAM identity (or administrative user), allow your account root/user with an External ID condition.

Save the following as `trust-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<YOUR_ACCOUNT_ID>:root"
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

*Note: Replace `<YOUR_ACCOUNT_ID>` with your 12-digit AWS account ID.*

---

## 3. Step 2: Create the IAM Read-Only Permission Policy

This policy grants only the read-only actions needed for topology discovery and flow log retrieval.

Save the following as `permissions-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Ec2TopologyReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeFlowLogs"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogsReadOnly",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents",
        "logs:GetLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3FlowLogsReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 4. Step 3: Deploy Role via AWS CLI

Run the following commands using the AWS CLI configured with administrator privileges:

```bash
# 1. Create the IAM Role with the Trust Policy
aws iam create-role \
  --role-name SecurityGatewayReadOnlyRole \
  --assume-role-policy-document file://trust-policy.json \
  --description "Strictly read-only role for Adaptive Security Gateway VPC discovery and telemetry"

# 2. Attach the Inline Least-Privilege Read-Only Policy
aws iam put-role-policy \
  --role-name SecurityGatewayReadOnlyRole \
  --policy-name SecurityGatewayReadOnlyPolicy \
  --policy-document file://permissions-policy.json
```

---

## 5. Step 4: Enabling VPC Flow Logs (If Not Already Configured)

The security gateway does not automatically create VPC Flow Logs. If your VPC does not have flow logs enabled, configure them manually:

### Option A: CloudWatch Logs Destination (Recommended for Real-Time Streaming)
```bash
# 1. Create a CloudWatch log group
aws logs create-log-group --log-group-name /aws/vpc/flowlogs

# 2. Create flow log delivery role and enable flow logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids <YOUR_VPC_ID> \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs \
  --deliver-logs-permission-arn <FLOW_LOGS_DELIVERY_ROLE_ARN>
```

### Option B: Amazon S3 Destination
```bash
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids <YOUR_VPC_ID> \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::<YOUR_FLOW_LOGS_BUCKET>
```

---

## 6. Step 5: Configure the Local Gateway Environment

Set the following variables in your local environment or `.env` file before launching the gateway:

### PowerShell (Windows):
```powershell
$env:AWS_REGION = "ap-southeast-2" # or your chosen AWS region
$env:AWS_ROLE_ARN = "arn:aws:iam::<YOUR_ACCOUNT_ID>:role/SecurityGatewayReadOnlyRole"
$env:AWS_EXTERNAL_ID = "AdaptiveGatewayAuth"
```

### Bash (Linux / macOS):
```bash
export AWS_REGION="ap-southeast-2"
export AWS_ROLE_ARN="arn:aws:iam::<YOUR_ACCOUNT_ID>:role/SecurityGatewayReadOnlyRole"
export AWS_EXTERNAL_ID="AdaptiveGatewayAuth"
```

---

## 7. Verification Checklist

1. **Verify Identity:** Run `aws sts assume-role --role-arn $env:AWS_ROLE_ARN --role-session-name TestSession --external-id $env:AWS_EXTERNAL_ID`.
2. **Launch Gateway Dashboard:** Navigate to `MultiCloudView`.
3. **Click "Test STS Identity":** State changes to **VERIFIED** and displays your 12-digit account ID.
4. **Click "Discover VPCs":** VPCs, Subnets, Route Tables, and Security Groups populate the inventory table.
5. **Click "Poll Live Logs":** Ingests real network traffic, runs XGBoost V2 threat evaluation, and records security events.

