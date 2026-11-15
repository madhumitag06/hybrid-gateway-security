# PHASE 18 — WORKSTREAM 1: TTL REMEDIATION REPORT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `https://github.com/madhumitag06/hybrid-gateway-security.git`  
**Branch:** `main`  
**Execution Phase:** Phase 18 Implementation  
**Status:** FULLY REMEDIATED & VERIFIED  

---

## 1. Executive Summary

| Inspection Item | Before Phase 18 (Defective) | After Phase 18 (Remediated) | Verification Status |
| :--- | :--- | :--- | :--- |
| **Renewal Semantics** | Cumulative addition (`expires_at += extra`) | Sliding-window refresh (`now + extra`) | **PASS (Verified)** |
| **Timer Accumulation** | Timers compounded (`97181s`, `3974s`) | Capped at configured window (`~300s`) | **PASS (Verified)** |
| **Repeated Flow Detections** | 324 flows yielded ~27 hours | 324 flows yield ~300 seconds | **PASS (0.0% inflation)** |
| **Longer Policy Preservation** | Unhandled | Preserved without premature shortening | **PASS (Verified)** |
| **Already-Expired Handling** | Unhandled | Rejected by `extend_ttl`, pruned to EXPIRED | **PASS (Verified)** |
| **Timezone Consistency** | Offset-naive vs aware risks | Strict UTC timezone normalization | **PASS (Verified)** |

---

## 2. Root Cause & Defect Description

In Phase 17, manual inspection revealed active containment rules with expiration timers of `3974s` and `97181s` for rules configured with a default TTL of 300s.

### The Defective Code:
In `backend/app/repositories/enforcement_repo.py`:
```python
# DEFECTIVE IMPLEMENTATION:
rule.expires_at = rule.expires_at + timedelta(seconds=extra_seconds)
rule.ttl_seconds += extra_seconds
```
Each arrival of a repeated flow matching an active rule performed cumulative addition on the expiration timestamp. For host `192.168.1.77`, receiving 324 flow records compounded its expiration date:
$$324 \times 300\text{ s} = 97,200\text{ s} \approx 27\text{ hours}$$

---

## 3. Remediated Sliding-Window Implementation

The sliding-window idle timeout was implemented in `backend/app/repositories/enforcement_repo.py`:

```python
def extend_ttl(self, rule_id: str, extra_seconds: int) -> Optional[ActiveEnforcementModel]:
    """
    Refresh the expiration time of an existing active or simulated rule using sliding-window semantics.
    Never compounds TTL by adding onto previous expiry; slides from current evaluation time.
    Preserves an explicitly longer existing expiration date.
    """
    rule = self.get_by_id(rule_id)
    if not rule or rule.status not in ("ACTIVE", "SIMULATED"):
        return None

    now = datetime.now(timezone.utc)
    cur_exp = rule.expires_at
    if cur_exp.tzinfo is None:
        cur_exp = cur_exp.replace(tzinfo=timezone.utc)

    # If already expired, do not extend
    if cur_exp <= now:
        return None

    # Sliding window: refresh expiration relative to current evaluation timestamp
    sliding_expiry = now + timedelta(seconds=extra_seconds)

    # Do not shorten an explicitly longer expiry if a policy requires preservation
    if sliding_expiry > cur_exp:
        rule.expires_at = sliding_expiry

    rule.ttl_seconds = max(rule.ttl_seconds, extra_seconds)
    rule.updated_at = now
    self.db.flush()
    return rule
```

---

## 4. Empirical Test Verification

Automated regression tests in `backend/tests/test_phase18_containment_lifecycle.py`:

1. **Test 1 — 324 Repeated Flow Evaluations:**
   - 1st repeat: Remaining TTL = `299s`
   - 13th repeat: Remaining TTL = `299s` (previously `~3,900s`)
   - 324th repeat: Remaining TTL = `299s` (previously `~97,200s`)
   - `rule.ttl_seconds` remained strictly `300`.
2. **Test 2 — Longer Policy Preservation:**
   - A host quarantined for 600s under `BRUTE_FORCE` received a 180s `Restrict` probe.
   - Expiration remained bounded by the 600s quarantine; no premature truncation occurred.
3. **Test 3 — Expired Rule Handling:**
   - An expired rule cannot be extended (`extend_ttl` returns `None`).
   - A subsequent detection creates a clean rule with a fresh ID and valid expiration.
