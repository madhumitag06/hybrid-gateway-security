# PHASE 10 TECHNICAL REPORT: AWS INVENTORY ROOT CAUSE & RECONCILIATION
**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `C:\Users\LENOVO\Desktop\hybrid-gateway-security`  
**Date:** 2026-11-15  
**Status:** COMPLETE & RECONCILED (10 AWS Resources Discovered & Idempotently Synced with 3 GCP Resources)

---

## 1. Observed Problem

On the Multi-Cloud page, the user observed:
1. The AWS card reported `CONNECTED`, but `Discovery: 0 resources`.
2. The Multi-Cloud Network Resource Inventory Table displayed only 3 rows, all of which belonged to Google Cloud Platform (`test-gcp-reg-01-vpc-test-gcp`, `test-gcp-reg-01-subnet-test-gcp`, `test-gcp-reg-01-fw-test-gcp`).
3. Zero Amazon Web Services resources appeared in the table, despite an established STS connection to AWS Account `698766075180` in region `ap-southeast-2`.

---

## 2. Root Cause Investigation

A rigorous trace from the frontend service through the FastAPI router and database layer uncovered two critical bottlenecks:

### Bottleneck A: Short-Circuit in `list_cloud_resources`
In `backend/app/api/v1/cloud.py`:
```python
@router.get("/resources", response_model=List[CloudResourceSchema])
def list_cloud_resources(
    provider: Optional[str] = Query(None, description="Filter by provider"),
    resource_type: Optional[str] = Query(None, description="Filter by type: VPC, SUBNET, GATEWAY, SECURITY_GROUP"),
    db: Session = Depends(get_db),
):
    db_res = CloudRegistry.list_resources(db, provider=provider, resource_type=resource_type)
    if db_res:
        # map and return db_res
        return schemas

    # Fallback to discover from live adapters only if db_res is empty
    ...
```
- When `MultiCloudView` mounted, it executed `cloudService.getResources()` without passing a provider filter (`provider=None`).
- The PostgreSQL database had 3 pre-existing GCP resources from initial seeding.
- `CloudRegistry.list_resources(db, provider=None)` found these 3 GCP rows (`len(db_res) == 3 > 0`).
- Because `db_res` was non-empty, the API immediately returned only those 3 rows. The live adapter discovery fallback (lines 614–640) was **never reached**.

### Bottleneck B: Missing Initial Discovery Trigger in Frontend
- `MultiCloudView.tsx` had a button to discover AWS resources (`handleDiscoverAws`), but on initial component mount (`loadData()`), it never triggered AWS resource discovery or passed `sync_live=true`.
- Consequently, if AWS resources were not yet persisted in PostgreSQL, the table permanently displayed only GCP rows.

### Bottleneck C: Verification of Live AWS Adapter Capabilities
To ensure the failure was not due to AWS permissions or STS issues, we tested `AwsAdapter.list_network_resources()` directly using `ml/.venv/Scripts/python.exe`:
```python
adapter = CloudConnectionManager.get_or_create_aws_adapter()
live_res = adapter.list_network_resources()
```
The AWS adapter successfully connected to AWS via `SecurityGatewayReadOnlyRole` (Account `698766075180`, Region `ap-southeast-2`) and discovered **10 real AWS resources**:
1. **VPC:** `vpc-0fc9db63fecb34fad` (CIDR: `172.31.0.0/16`)
2. **Subnet:** `subnet-0e81e8f4520eb0840` (Zone: `ap-southeast-2a`, CIDR: `172.31.16.0/20`)
3. **Subnet:** `subnet-0bd9ce3cdaefe3397` (Zone: `ap-southeast-2b`, CIDR: `172.31.32.0/20`)
4. **Subnet:** `subnet-033bb3a9f29565a7c` (Zone: `ap-southeast-2c`, CIDR: `172.31.0.0/20`)
5. **Route Table:** `rtb-086b50f0c0484be2a` (Main table for `vpc-0fc9db63fecb34fad`)
6. **Security Group:** `sg-06e452b75377f63e3` (`ASG-Temporary-Test-SG`)
7. **Security Group:** `sg-0f84bd0fd243b8649` (`default`)
8. **Network ACL:** `acl-0d4adb09d5fb0becd` (Default NACL)
9. **Internet Gateway:** `igw-00159811a9c4fdfdd` (Attached to `vpc-0fc9db63fecb34fad`)
10. **Flow Log Subscription:** `fl-0d236b31b1fd0d13e` (CloudWatch log group: `/aws/vpc/flowlogs/ap-southeast-2-default`)

---

## 3. Implemented Fix & Safeguards

### Safeguard Compliance:
1. **Idempotent Upserts:** Synced via `CloudRegistry.sync_resources` using composite keys (`f"{account.id}-{r.resource_id}"`) to prevent duplicate row creation.
2. **No Redundant Discovery on Routine Refresh:** The backend checks if AWS resources already exist in `cloud_resources`. Once discovered (10 rows), subsequent polls query PostgreSQL directly without invoking AWS EC2 API calls.
3. **Preservation of Existing GCP Inventory:** All 3 GCP records (`vpc-test-gcp`, `subnet-test-gcp`, `fw-test-gcp`) are fully preserved in PostgreSQL alongside the 10 AWS records.

### Code Modifications:
1. **`backend/app/api/v1/cloud.py`**:
   - Added `sync_live: bool = Query(False)` to `list_cloud_resources`.
   - When `sync_live=False` and AWS has 0 rows in PostgreSQL, the handler automatically discovers AWS network resources once and commits them to the database.
   - Preserved correct relationship mapping (`parent_resource_id` -> `vpc_id`).
2. **`backend/app/cloud/services/cloud_registry.py`**:
   - In `get_inventory_summary`, if `resources` does not contain any AWS resources (`not any(r.provider == 'AWS' for r in resources)`), auto-sync AWS once so summary metrics include both providers.
3. **`src/services/cloud.ts`**:
   - Updated `getResources` to support `syncLive?: boolean`.
   - Added `id?: string` to `CloudResource` interface.
4. **`src/components/MultiCloudView.tsx`**:
   - Table now renders all 13 discovered resources (10 AWS + 3 GCP) with live provider filter chips (`ALL`, `AWS`, `GCP`, `AZURE`, `DOCKER_LAB`) and resource type filters.

---

## 4. Verification & Results

- **PostgreSQL Database Verification:**
  - Before: 3 total rows (3 GCP, 0 AWS).
  - After: 13 total rows (10 AWS, 3 GCP).
  - Idempotency test: Re-running `sync_resources` produces 10 synced items, exactly 13 total rows in PostgreSQL (zero duplicates created).
- **Inventory Summary Output:**
  ```json
  {
    "total_resources": 13,
    "total_vpcs": 2,
    "total_subnets": 4,
    "total_security_groups": 3,
    "total_gateways": 1,
    "by_provider": {
      "GCP": 3,
      "AWS": 10
    }
  }
  ```
- **Interactive Visual Verification:**
  - `NOT TESTED — MANUAL USER VERIFICATION REQUIRED` (Subject to localhost testing restriction). The user can navigate to `/multi-cloud` and verify that the resource inventory table displays all 10 AWS rows and 3 GCP rows.
