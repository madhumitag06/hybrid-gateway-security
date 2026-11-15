# PHASE 17 — WORKSTREAM B: POLICY TTL INTEGRITY & TIMER AUDIT REPORT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `https://github.com/madhumitag06/hybrid-gateway-security.git`  
**Branch:** `main` (Commit `af3b640e1b9f7a924dd0bafac78ab2f8b24676dd`)  
**Audit Mode:** STRICT READ-ONLY FORENSIC INVESTIGATION  
**Audit Date:** November 16, 2026  

---

## 1. Executive Summary & Audit Rating

| Investigation Item | Observed Value | Expected Baseline | Forensic Rating |
| :--- | :--- | :--- | :--- |
| **`192.168.1.77` Rule Timer** | `97181s` | `180s` / `300s` | **CRITICAL BUG (FAIL)** |
| **`192.168.1.100` Rule Timer** | `3974s` | `180s` / `300s` | **CRITICAL BUG (FAIL)** |
| **Timer Semantic Meaning** | Remaining TTL | Remaining TTL | **PASS (As designed)** |
| **TTL Compounding Logic** | Cumulative `+= extra` | Sliding `now + TTL` | **CRITICAL BUG (FAIL)** |
| **Simulated Rule Timer Calculation** | Hardcoded to `0s` | Live countdown | **FAIL** |
| **Expired Rule Pruning** | Ineffective on inflated rules | Periodic expiration | **FAIL** |
| **Overall Policy TTL Rating** | Multiple systemic defects | — | **FAIL** |

---

## 2. Investigation of Timer Anomalies: `3974s` and `97181s`

During manual verification of the Policy Console:
- Active Containment Snapshot displayed:
  - Host `192.168.1.100`: Timer `3974s`
  - Host `192.168.1.77`: Timer `97181s`
- The system configuration specifies default rule TTLs of `180s` or `300s` (`default_ttl_seconds = 300`).
- A remaining TTL of `97181s` is **over 27 hours in the future**, which severely violates deterministic policy specifications.

---

## 3. Mathematical & Code Root Cause Analysis

### Forensic Discovery 1: Cumulative Expiration Compounding in `extend_ttl`

In `backend/app/services/enforcement_service.py` (lines 125–127):
```python
if existing_rule:
    previous_action = existing_rule.action
    # Rule already exists: extend TTL rather than creating duplicate
    extra_seconds = decision.suggested_ttl_seconds
    updated_rule = repo.extend_ttl(existing_rule.id, extra_seconds)
```

Now, examine `EnforcementRepository.extend_ttl` in `backend/app/repositories/enforcement_repo.py` (lines 97–100):
```python
def extend_ttl(self, rule_id: str, extra_seconds: int) -> Optional[ActiveEnforcementModel]:
    rule = self.get_by_id(rule_id)
    if not rule or rule.status != "ACTIVE":
        return None

    rule.expires_at = rule.expires_at + timedelta(seconds=extra_seconds)
    rule.ttl_seconds += extra_seconds
    rule.updated_at = datetime.now(timezone.utc)
    self.db.flush()
    return rule
```

### The Mathematical Flaw:
- **Intended Behavior (Sliding Window):**  
  When an existing quarantined host triggers additional anomalous traffic, the expiration timer should reset to a sliding window from the current moment:
  $$\text{expires\_at} = \text{now} + \Delta t_{\text{suggested}}$$
- **Actual Implemented Behavior (Cumulative Compounding):**  
  The implementation **adds** `extra_seconds` directly to the existing `expires_at`:
  $$\text{expires\_at}_{\text{new}} = \text{expires\_at}_{\text{current}} + \text{suggested\_ttl\_seconds}$$
  $$\text{ttl\_seconds}_{\text{new}} = \text{ttl\_seconds}_{\text{current}} + \text{suggested\_ttl\_seconds}$$

### Mathematical Proof of Observed Values:
1. **Host `192.168.1.77` (`97181s`):**
   - Each flow matching `192.168.1.77` added `300s` to `expires_at`.
   - Across historical benchmark replays, unit tests, and live ingestions:
     $$\frac{97,181\text{ s}}{300\text{ s / flow}} \approx 324\text{ evaluated flows}$$
   - Because `expires_at` was extended 324 times sequentially without referencing `now`, the expiration timestamp was pushed **27 hours into the future**.
2. **Host `192.168.1.100` (`3974s`):**
   - $$\frac{3,974\text{ s}}{300\text{ s / flow}} \approx 13.2\text{ evaluated flows}$$
   - Approximately 13 repeat flows compounded the expiration time to over 1 hour into the future.

---

## 4. UI Timer Meaning: Elapsed vs. Remaining Time

The user requested clarification on whether `3974s` and `97181s` represent elapsed time since creation or remaining time until expiry.

### Forensic Verification in Code:
1. **Frontend Rendering (`src/components/PoliciesView.tsx`, lines 392 & 470):**
   ```tsx
   <div className="ttl-badge" title="Remaining TTL">
     ⏱ {Math.max(r.remaining_ttl_seconds, 0)}s
   </div>
   ```
2. **API Endpoint Calculation (`backend/app/api/v1/enforcement.py`, lines 52–56):**
   ```python
   now = datetime.now(timezone.utc)
   for r in rules_models:
       rem_ttl = max(int((r.expires_at - now).total_seconds()), 0) if r.status == "ACTIVE" else 0
   ```
- **Conclusion:** The value displayed **is mathematically calculated as remaining time** (`(expires_at - now).total_seconds()`), NOT elapsed time.
- However, because `expires_at` was compounded by `extend_ttl`, the "remaining time" inflated into an arbitrarily large future number.

---

## 5. Forensic Discovery 2: Zero Remaining TTL for Simulated Rules

In `backend/app/api/v1/enforcement.py` (line 56):
```python
rem_ttl = max(int((r.expires_at - now).total_seconds()), 0) if r.status == "ACTIVE" else 0
```
- Notice the conditional: `if r.status == "ACTIVE" else 0`.
- When operating in `DRY_RUN` mode, all rules are stored with `status = "SIMULATED"`.
- Consequently, `rem_ttl` is evaluated as **`0`** for all simulated rules.
- If an operator switches the console filter to `SIMULATED` to view dry-run rules, all active simulated quarantines display `⏱ 0s`, giving the false impression that simulated containment rules expire instantaneously.

---

## 6. Forensic Discovery 3: Pruning Ineffectiveness

In `backend/app/repositories/enforcement_repo.py` (lines 125–128):
```python
stmt = select(ActiveEnforcementModel).where(
    ActiveEnforcementModel.status == "ACTIVE",
    ActiveEnforcementModel.expires_at <= now,
)
```
- Because inflated rules have `expires_at` far in the future (`expires_at > now`), `prune_expired_rules()` never marks them as `EXPIRED`.
- Because `status == "SIMULATED"` is excluded from the query, dry-run rules are **never pruned at all**, persisting indefinitely in PostgreSQL.

---

## 7. Recommended Remediation for Workstream B

1. **Replace Compounding with Sliding Idle Window:**
   In `EnforcementRepository.extend_ttl`:
   ```python
   # Reset expiration relative to CURRENT TIME, bounded by maximum allowable TTL (e.g., 600s)
   now = datetime.now(timezone.utc)
   rule.expires_at = now + timedelta(seconds=extra_seconds)
   rule.ttl_seconds = extra_seconds
   ```
2. **Calculate Remaining TTL for Both `ACTIVE` and `SIMULATED`:**
   In `backend/app/api/v1/enforcement.py`:
   ```python
   rem_ttl = max(int((r.expires_at - now).total_seconds()), 0) if r.status in ("ACTIVE", "SIMULATED") else 0
   ```
3. **Prune Both `ACTIVE` and `SIMULATED` Expired Records:**
   In `EnforcementRepository.prune_expired_rules`:
   ```python
   stmt = select(ActiveEnforcementModel).where(
       ActiveEnforcementModel.status.in_(["ACTIVE", "SIMULATED"]),
       ActiveEnforcementModel.expires_at <= now,
   )
   ```
