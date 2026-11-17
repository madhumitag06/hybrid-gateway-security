# PHASE 18 — WORKSTREAM 3: DRY_RUN VISIBILITY & REMAINING TTL REPORT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `https://github.com/madhumitag06/hybrid-gateway-security.git`  
**Branch:** `main`  
**Execution Phase:** Phase 18 Implementation  
**Status:** FULLY REMEDIATED & VERIFIED  

---

## 1. Executive Summary

| Visibility Item | Before Phase 18 | After Phase 18 | Verification Status |
| :--- | :--- | :--- | :--- |
| **Default Console Status Filter** | Hardcoded `statusFilter='ACTIVE'` | Defaults to `''` ("All Statuses") | **PASS (Remediated)** |
| **Simulated Rules Visibility** | Hidden from default views | Visibly displayed by default | **PASS (Remediated)** |
| **Port Scan IP `192.168.10.55`** | Invisible in active snapshot | Visible with `Block`, `SIMULATED`, live TTL | **PASS (Verified)** |
| **Remaining TTL for Simulated Rules** | Hardcoded to `0s` (`if ACTIVE else 0`) | Live calculated `(expires_at - now)` | **PASS (Remediated)** |
| **Active Snapshot Rendering** | Only historical active rules | Active & simulated unexpired rules | **PASS (Remediated)** |
| **Status vs TTL Separation** | Conflated | Distinct badges for status and remaining TTL | **PASS (Remediated)** |

---

## 2. Root Cause of Invisible Port-Scan Reconnaissance Rules

In Phase 17, manual inspection of the Port Scan Reconnaissance fixture revealed that while host `192.168.10.55` was successfully classified as `PORT_SCAN` with action `Block`, the rule never appeared in the active containment snapshot.

### The Two Underlying Defects:
1. **Frontend Filter Default:**
   In `src/components/PoliciesView.tsx`:
   ```typescript
   const [statusFilter, setStatusFilter] = useState<string>('ACTIVE')
   ```
   The frontend requested only `status=ACTIVE` from the API, filtering out all simulated rules created under `DRY_RUN` mode.
2. **Backend Forced Zero TTL:**
   In `backend/app/api/v1/enforcement.py`:
   ```python
   rem_ttl = max(int((r.expires_at - now).total_seconds()), 0) if r.status == "ACTIVE" else 0
   ```
   Even when an operator manually filtered by `SIMULATED`, the remaining TTL was hardcoded to `0`, causing the UI to display `⏱ 0s`.

---

## 3. Remediated Visibility & TTL Calculation

### A. API Endpoint Correction (`backend/app/api/v1/enforcement.py`)
```python
for r in rules_models:
    rem_ttl = 0
    if r.expires_at is not None and r.status in ("ACTIVE", "SIMULATED"):
        exp_dt = r.expires_at
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        seconds_left = int((exp_dt - now).total_seconds())
        if seconds_left > 0:
            rem_ttl = seconds_left

    results.append(
        ActiveEnforcementRule(
            rule_id=r.id,
            target_ip=r.target_ip,
            target_port=r.target_port,
            protocol=r.protocol or "ANY",
            action=r.action,
            status=r.status,
            mode=r.mode,
            reason=r.reason,
            ttl_seconds=r.ttl_seconds,
            expires_at=r.expires_at,
            remaining_ttl_seconds=rem_ttl,
            created_at=r.created_at,
            revoked_at=r.revoked_at,
            revoked_by=r.revoked_by,
        )
    )
```

### B. Frontend Default Filter and Snapshot (`src/components/PoliciesView.tsx`)
1. **Default Filter:**
   ```typescript
   const [statusFilter, setStatusFilter] = useState<string>('')
   ```
2. **Clear Dropdown Choices:**
   - `""`: All Statuses (Active, Simulated, Expired, Revoked)
   - `"ACTIVE"`: ACTIVE (Enforced)
   - `"SIMULATED"`: SIMULATED (DRY_RUN)
   - `"EXPIRED"`: EXPIRED
   - `"REVOKED"`: REVOKED
3. **Overview Active Containment Snapshot:**
   Filters for non-expired containment rules (`status in ('ACTIVE', 'SIMULATED') && remaining_ttl_seconds > 0`), ensuring simulated quarantines like `192.168.10.55` are immediately visible with their `SIMULATED` badge and remaining countdown.
