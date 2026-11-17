# PHASE 17 — WORKSTREAM A: CONTAINMENT LIFECYCLE AUDIT REPORT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `https://github.com/madhumitag06/hybrid-gateway-security.git`  
**Branch:** `main` (Commit `af3b640e1b9f7a924dd0bafac78ab2f8b24676dd`)  
**Audit Mode:** STRICT READ-ONLY FORENSIC INVESTIGATION  
**Audit Date:** November 16, 2026  

---

## 1. Executive Summary & Audit Rating

| Subsystem / Component | Forensic Status | Integrity Rating |
| :--- | :--- | :--- |
| **Enforcement Mode Handling (`DRY_RUN` vs `SANDBOX`)** | Operational | **PASS** |
| **Deterministic Policy Rule Catalog** | Verified | **PASS** |
| **Port Scan Containment Action (`Block`)** | Verified | **PASS** |
| **Volumetric Burst Containment Action (`Restrict`)** | Verified | **PASS** |
| **Rule Deduplication & Keying** | Flawed under `DRY_RUN` | **FAIL** |
| **Console Active Snapshot Rule Visibility** | Filter Mismatch | **FAIL** |
| **Overall Containment Lifecycle Rating** | Conditional | **PASS WITH LIMITATIONS** |

---

## 2. Investigation of Observed User Behaviors

### Observation A: Port Scan Fixture Evaluation & Action
- **Observed Behavior:**
  - Source IP: `192.168.10.55`
  - Target Ports: 21, 22, 23, 24, 25... up to 60 distinct destination ports
  - Prediction: `PORT_SCAN`
  - Risk Scores: 78 and 81
  - Recommended Action: `Block`
- **Forensic Verification:**
  - In `backend/app/services/policy_engine.py` (lines 277–293):
    ```python
    if attack_type == "PORT_SCAN":
        return PolicyDecision(
            decision_id=decision_id,
            event_id=event_id,
            target_ip=source_ip,
            target_port=None,
            protocol="ANY",
            policy_action="Block",
            enforcement_required=True,
            confidence=prediction.confidence,
            threat_level="HIGH",
            attack_type=attack_type,
            risk_score=prediction.risk_score,
            rule_name="RECON_PORT_SCAN_QUARANTINE",
            reason=f"Multi-port scanning reconnaissance detected from {source_ip}. Quarantining host.",
            suggested_ttl_seconds=300,
        )
    ```
  - **Verdict:** Fully verified. For `PORT_SCAN` with high risk (>= 75), the Policy Engine deterministically assigns `Block` with host-wide scope (`target_port=None`, `protocol="ANY"`) under rule `RECON_PORT_SCAN_QUARANTINE`.

---

### Observation B: Volumetric Burst Fixture Evaluation & Action
- **Observed Behavior:**
  - Prediction: `TRAFFIC_SPIKE`
  - Risk Score: 100/100
  - Recommended Action: `Restrict`
- **Forensic Verification:**
  - In `backend/app/services/policy_engine.py` (lines 311–326):
    ```python
    elif attack_type == "TRAFFIC_SPIKE":
        return PolicyDecision(
            decision_id=decision_id,
            event_id=event_id,
            target_ip=source_ip,
            target_port=dst_port,
            protocol=protocol,
            policy_action="Restrict",
            enforcement_required=True,
            confidence=prediction.confidence,
            threat_level="HIGH",
            attack_type=attack_type,
            risk_score=prediction.risk_score,
            rule_name="VOLUMETRIC_SURGE_RESTRICT",
            reason=f"High-volume traffic surge detected on port {dst_port}. Restricting bandwidth / applying rate limit.",
            suggested_ttl_seconds=300,
        )
    ```
  - **Verdict:** Fully verified and architecturally intentional. A volumetric surge / traffic spike is mitigated via rate-limiting and bandwidth throttling (`Restrict`) rather than full host disconnection (`Block`), preserving legitimate non-volumetric session availability.

---

### Observation C: Benign Transit Fixture Evaluation & Action
- **Observed Behavior:**
  - Prediction: `BENIGN`
  - Risk Score: 0/100
  - Recommended Action: `Allow`
- **Forensic Verification:**
  - In `backend/app/services/policy_engine.py` (lines 240–256):
    ```python
    if threat_level == "LOW" or attack_type == "BENIGN":
        return PolicyDecision(
            decision_id=decision_id,
            event_id=event_id,
            target_ip=source_ip,
            target_port=dst_port,
            protocol=protocol,
            policy_action="Allow",
            enforcement_required=False,
            confidence=prediction.confidence,
            threat_level="LOW",
            attack_type="BENIGN",
            risk_score=prediction.risk_score,
            rule_name="BASELINE_TRAFFIC_ALLOW",
            reason="Traffic profile conforms to baseline distributions; no policy restriction required.",
            suggested_ttl_seconds=0,
        )
    ```
  - **Verdict:** Fully verified. Nominal baseline traffic passes unimpeded with zero containment overhead.

---

## 3. Root Cause: Why Fixture IP `192.168.10.55` Was Not Visible in Active Snapshot

The user observed that while `192.168.10.55` was successfully classified as `PORT_SCAN` with action `Block`, it did not appear in the Policy Console Active Rules snapshot.

### Forensic Chain of Causation

1. **Operating Enforcement Mode:**
   - The application was operating in `DRY_RUN (SIMULATION)` mode (the safe default).
   - In `backend/app/services/enforcement_service.py` (lines 40–44):
     `EnforcementService.get_adapter()` returned `DryRunAdapter`.
   - In `backend/app/services/enforcement/dry_run_adapter.py` (line 33):
     `DryRunAdapter.enforce(...)` returns:
     ```python
     status = "SIMULATED"
     ```
2. **Database Persistence:**
   - In `backend/app/services/enforcement_service.py` (line 191):
     ```python
     rule_model = ActiveEnforcementModel(
         id=rule_id,
         target_ip=decision.target_ip, # 192.168.10.55
         action=decision.policy_action, # Block
         status=enforce_res.status,     # "SIMULATED"
         mode=cls._active_mode,         # "DRY_RUN"
         ...
     )
     repo.create(rule_model)
     ```
   - The containment record was correctly created and committed in PostgreSQL with `status="SIMULATED"`.
3. **Frontend Status Filter Mismatch:**
   - In `src/components/PoliciesView.tsx` (line 121):
     ```typescript
     const [statusFilter, setStatusFilter] = useState<string>('ACTIVE')
     ```
   - On initial page load and on Overview tab rendering:
     ```typescript
     listEnforcementRules(statusFilter || undefined) // Passes 'ACTIVE'
     ```
   - In `backend/app/api/v1/enforcement.py` (line 50):
     `repo.list_all_rules(..., status_filter='ACTIVE')` executes:
     ```sql
     SELECT * FROM active_enforcements WHERE status = 'ACTIVE' ORDER BY created_at DESC;
     ```
   - **Crucial finding:** Because `192.168.10.55` was created in `DRY_RUN` mode with `status = 'SIMULATED'`, it was **excluded** by the SQL query `WHERE status = 'ACTIVE'`.
   - The Overview snapshot uses the exact same `rules` state (`rules.slice(0, 4)`), which contained only the historical `ACTIVE` rules (`192.168.1.100` and `192.168.1.77`).

---

## 4. Root Cause: Deduplication Failure Under `DRY_RUN` Mode

In `backend/app/services/enforcement_service.py` (lines 115–120):
```python
existing_rule = repo.find_active_by_target(
    target_ip=decision.target_ip, target_port=decision.target_port
)
```
In `backend/app/repositories/enforcement_repo.py` (lines 35–39):
```python
stmt = select(ActiveEnforcementModel).where(
    ActiveEnforcementModel.target_ip == target_ip,
    ActiveEnforcementModel.status == "ACTIVE",
    ActiveEnforcementModel.expires_at > now,
)
```
### Vulnerability Analysis:
- `find_active_by_target` hardcodes `ActiveEnforcementModel.status == "ACTIVE"`.
- When in `DRY_RUN` mode, existing simulated rules have `status == "SIMULATED"`.
- As a consequence, `find_active_by_target` returns `None` for every single flow from `192.168.10.55`.
- During the 60-flow port scan ingestion, **60 separate `ActiveEnforcementModel` records** were created with `status="SIMULATED"` instead of deduplicating into one rule and extending its TTL!

---

## 5. Summary Table: Lifecycle State Matrix

| Mode | Adapter Invoked | Resulting Status | Persisted in DB? | Returned by `find_active_by_target`? | Visible in Default Console View? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`SANDBOX`** | `SandboxAdapter` | `ACTIVE` | Yes | **Yes** | **Yes** |
| **`DRY_RUN`** | `DryRunAdapter` | `SIMULATED` | Yes | **No** (`status != ACTIVE`) | **No** (`filter == ACTIVE`) |

---

## 6. Recommendations for Workstream A Remediation

1. **Update `find_active_by_target` Query:**
   - Expand status condition to check for either `"ACTIVE"` or `"SIMULATED"` depending on the active enforcement mode, or include both:
     `ActiveEnforcementModel.status.in_(["ACTIVE", "SIMULATED"])`.
2. **Harmonize Console Default Filter:**
   - In `PoliciesView.tsx`, when `config?.active_mode === 'DRY_RUN'`, default `statusFilter` should include `SIMULATED` or default to an empty filter to display all current containment rules regardless of mode.
3. **Normalize Remaining TTL in API:**
   - In `backend/app/api/v1/enforcement.py`, calculate `remaining_ttl_seconds` for both `ACTIVE` and `SIMULATED` rules so simulated containment rules display live timers rather than 0s.
