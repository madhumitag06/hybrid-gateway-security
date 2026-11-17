# PHASE 9 REPORT: MULTI-CLOUD INVENTORY CONSISTENCY & DATA MODEL REPAIR

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Deliverable:** Multi-Cloud Inventory Data Model Synchronization & UI Consistency  
**Date:** November 15, 2026  
**Status:** RESOLVED & VERIFIED  

---

## 1. Executive Summary

This report documents the resolution of the bug where the Multi-Cloud page previously displayed **zero resource rows** even after AWS discovery succeeded.

The failure was traced to an object-model attribute mismatch between `CloudResourceModel` (SQLAlchemy) and `CloudResourceSchema` (Pydantic) in `backend/app/api/v1/cloud.py`. Persisted database resources triggered runtime `AttributeError` exceptions when converted to schemas, resulting in an empty table while summary counts succeeded.

By correcting the field mappings, properly handling `parent_resource_id` according to resource type, and updating the frontend inventory table with provenance badges, inventory consistency is 100% restored.

---

## 2. Root Cause Analysis & Model Discrepancy

### 2.1 The Model vs Schema Mismatch
When `CloudRegistry.list_resources(db)` retrieved rows from PostgreSQL, `list_cloud_resources` attempted to instantiate `CloudResourceSchema` using attributes that do not exist on `CloudResourceModel`:

| Requested Schema Field | Non-Existent Model Attribute (Crash Point) | Correct `CloudResourceModel` Column |
|:---|:---|:---|
| `account_id` | `r.account_id` $\to$ `AttributeError` | `r.cloud_account_id` |
| `name` | `r.name` $\to$ `AttributeError` | `r.resource_name` |
| `vpc_id` | `r.vpc_id` $\to$ `AttributeError` | Contextual derivation (`r.parent_resource_id` or `r.resource_id`) |
| `state` | `r.state` $\to$ `AttributeError` | `r.metadata_json.get("state", "available")` |
| `zone` | `r.zone` $\to$ `AttributeError` | `r.metadata_json.get("zone")` |
| `tags` | `r.tags` $\to$ `AttributeError` | `r.metadata_json.get("tags", {})` |
| `created_at` | `r.created_at` $\to$ `AttributeError` | `r.discovered_at` |

Because `get_inventory_summary` only accessed `r.resource_type` (which exists on the model), summary cards rendered counts (e.g. 7 resources), while the `/resources` endpoint crashed and returned an empty array to the frontend.

---

## 3. Implemented Fixes

### 3.1 Resource-Type Aware Hierarchy Mapping (`backend/app/api/v1/cloud.py`)
In accordance with technical corrections, `parent_resource_id` is mapped contextually according to the specific resource type rather than blindly assumed to be a VPC:

```python
# Context-aware relationship resolution
if r.resource_type in ("VPC", "VNET"):
    vpc_id = r.resource_id
elif "vpc_id" in meta:
    vpc_id = meta["vpc_id"]
elif r.resource_type in (
    "SUBNET",
    "ROUTE_TABLE",
    "SECURITY_GROUP",
    "NETWORK_ACL",
    "GATEWAY",
    "INTERNET_GATEWAY",
    "NAT_GATEWAY",
):
    vpc_id = r.parent_resource_id
else:
    vpc_id = None
```

### 3.2 Inventory Summary Synchronization (`cloud_registry.py`)
`CloudRegistry.get_inventory_summary` was updated to ensure `total_resources` reflects `len(resources)` in the database, including Route Tables, Network ACLs, and Flow Log Subscriptions:

```python
return CloudInventorySummary(
    total_resources=len(resources),
    total_vpcs=vpc_count,
    vpcs_count=vpc_count,
    total_subnets=subnet_count,
    subnets_count=subnet_count,
    total_security_groups=sg_count,
    security_groups_count=sg_count,
    total_gateways=gw_count,
    gateways_count=gw_count,
    firewall_rules_count=fw_count,
    interfaces_count=if_count,
    by_provider=by_provider,
)
```

### 3.3 Provenance Badges in `MultiCloudView.tsx`
The inventory table in `MultiCloudView.tsx` now explicitly displays:
- **Parent / VPC Column**: Shows the enclosing VPC ID or parent resource identifier.
- **Provenance Column**: Displays visual badges:
  - `LIVE DISCOVERED`: For resources verified live through the AWS provider adapter.
  - `PERSISTED CACHE`: For resources cached in PostgreSQL.
  - `SIMULATED LAB`: For simulated Docker hybrid-lab resources.

---

## 4. Verification

1. **Schema Mapping Test**: Verified via `test_aws_adapter.py` and `CloudResourceSchema` validation.
2. **Count & Row Consistency**:
   - Live AWS VPC (`vpc-0fc9db63fecb34fad`)
   - Live Subnets: 3 subnets (`ap-southeast-2a`, `2b`, `2c`)
   - Live Security Group: 1 default SG
   - Live Route Table: 1 main route table
   - Live Flow Log Subscription: 1 flow log
   - Summary count: **7** | Table rows: **7** | Discrepancy: **0**.
