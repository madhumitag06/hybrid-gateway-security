# AWS VPC Inventory & Topology Discovery Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Provider:** Amazon Web Services (AWS)  
**Component:** `AwsCloudAdapter` Topology Discovery Engine  
**Date:** November 15, 2026  

---

## 1. Overview & Discovery Architecture

The AWS Topology Discovery Engine performs paginated, read-only inspection of Amazon EC2 networking resources. When authenticated via STS temporary credentials, the adapter queries six EC2 describe endpoints:

```
                  ┌─────────────────────────────────────────┐
                  │          AwsCloudAdapter                │
                  │      (Temporary STS Session)            │
                  └────────────────────┬────────────────────┘
                                       │
        ┌──────────────┬───────────────┼───────────────┬──────────────┐
        ▼              ▼               ▼               ▼              ▼
 ┌─────────────┐┌─────────────┐┌───────────────┐┌─────────────┐┌───────────────┐
 │ ec2:        ││ ec2:        ││ ec2:          ││ ec2:        ││ ec2:          │
 │ DescribeVpcs││ Describe    ││ DescribeRoute ││ Describe    ││ Describe      │
 │             ││ Subnets     ││ Tables        ││ Security    ││ NetworkAcls   │
 │             ││             ││               ││ Groups      ││               │
 └──────┬──────┘└──────┬──────┘└───────┬───────┘└──────┬──────┘└───────┬───────┘
        │              │               │               │               │
        └──────────────┴───────────────┼───────────────┴───────────────┘
                                       ▼
                       ┌───────────────────────────────┐
                       │ ec2:DescribeFlowLogs          │
                       │ (CloudWatch vs S3 Subscriptions│
                       └───────────────┬───────────────┘
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │ CloudRegistry.sync_resources()│
                       │ (PostgreSQL CloudResourceModel│
                       └───────────────────────────────┘
```

---

## 2. Discovered Resource Schema & Mapping

Each discovered resource is normalized into the common `CloudResourceSchema`:

| AWS Resource | Resource Type | Identifier Format | Schema Mapping |
| :--- | :--- | :--- | :--- |
| **Virtual Private Cloud** | `VPC` | `vpc-[0-9a-f]{17}` | `resource_id`, `cidr_block`, `state`, `tags`, `extra_data.is_default` |
| **Subnet** | `SUBNET` | `subnet-[0-9a-f]{17}` | `resource_id`, `vpc_id`, `zone`, `cidr_block`, `extra_data.available_ip_count` |
| **Route Table** | `ROUTE_TABLE` | `rtb-[0-9a-f]{17}` | `resource_id`, `vpc_id`, `extra_data.routes_count`, `extra_data.associations_count` |
| **Security Group** | `SECURITY_GROUP` | `sg-[0-9a-f]{17}` | `resource_id`, `vpc_id`, `name`, `extra_data.ingress_rules_count`, `extra_data.egress_rules_count` |
| **Network ACL** | `NETWORK_ACL` | `acl-[0-9a-f]{17}` | `resource_id`, `vpc_id`, `extra_data.entries_count`, `extra_data.is_default` |
| **VPC Flow Log** | `FLOW_LOG_SUBSCRIPTION` | `fl-[0-9a-f]{17}` | `resource_id`, `vpc_id`, `extra_data.destination_type`, `extra_data.destination`, `state` |

---

## 3. Discovered Resource Inventory (Verification Fixture)

The verification test suite (`test_aws_read_only_integration.py::test_aws_resource_discovery_mocked_ec2`) evaluated the full paginated inventory breakdown:

```json
{
  "total_resources": 6,
  "counts_by_type": {
    "VPC": 1,
    "SUBNET": 1,
    "ROUTE_TABLE": 1,
    "SECURITY_GROUP": 1,
    "NETWORK_ACL": 1,
    "FLOW_LOG_SUBSCRIPTION": 1
  },
  "resources": [
    {
      "resource_id": "vpc-0a1b2c3d4e5f67890",
      "provider": "AWS",
      "resource_type": "VPC",
      "name": "Production-VPC",
      "cidr_block": "10.0.0.0/16",
      "region": "us-east-1",
      "state": "available",
      "tags": { "Name": "Production-VPC" },
      "extra_data": {
        "is_default": false,
        "cidr_associations": ["10.0.0.0/16"]
      }
    },
    {
      "resource_id": "subnet-0123456789abcdef0",
      "provider": "AWS",
      "resource_type": "SUBNET",
      "name": "Public-Subnet-1",
      "cidr_block": "10.0.1.0/24",
      "region": "us-east-1",
      "zone": "us-east-1a",
      "vpc_id": "vpc-0a1b2c3d4e5f67890",
      "state": "available",
      "tags": { "Name": "Public-Subnet-1" }
    },
    {
      "resource_id": "rtb-0123456789abcdef0",
      "provider": "AWS",
      "resource_type": "ROUTE_TABLE",
      "name": "Main-RouteTable",
      "vpc_id": "vpc-0a1b2c3d4e5f67890",
      "region": "us-east-1",
      "state": "active",
      "extra_data": {
        "routes_count": 1,
        "associations_count": 1
      }
    },
    {
      "resource_id": "sg-0123456789abcdef0",
      "provider": "AWS",
      "resource_type": "SECURITY_GROUP",
      "name": "web-tier-sg",
      "vpc_id": "vpc-0a1b2c3d4e5f67890",
      "region": "us-east-1",
      "state": "active",
      "extra_data": {
        "description": "Allow HTTPS ingress",
        "ingress_rules_count": 1,
        "egress_rules_count": 1
      }
    },
    {
      "resource_id": "acl-0123456789abcdef0",
      "provider": "AWS",
      "resource_type": "NETWORK_ACL",
      "name": "Default-NACL",
      "vpc_id": "vpc-0a1b2c3d4e5f67890",
      "region": "us-east-1",
      "state": "active",
      "extra_data": {
        "is_default": true,
        "entries_count": 1
      }
    },
    {
      "resource_id": "fl-0123456789abcdef0",
      "provider": "AWS",
      "resource_type": "FLOW_LOG_SUBSCRIPTION",
      "name": "VPC-All-FlowLogs",
      "vpc_id": "vpc-0a1b2c3d4e5f67890",
      "region": "us-east-1",
      "state": "ACTIVE",
      "extra_data": {
        "traffic_type": "ALL",
        "destination_type": "cloud-watch-logs",
        "destination": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc/flowlogs",
        "deliver_logs_status": "SUCCESS"
      }
    }
  ]
}
```

---

## 4. PostgreSQL Persistence & Synchronization

When `POST /api/v1/cloud/accounts/AWS/discover` is executed:
1. `CloudRegistry.sync_resources()` upserts records into `CloudResourceModel` using composite key `<account_id>-<resource_id>`.
2. Existing resources have metadata, tags, and state updated in place without data loss.
3. Removed or missing resources remain logged for historical compliance.
4. Summary counts are instantly reflected in `CloudRegistry.get_inventory_summary()` and displayed in the frontend dashboard.

