# Phase 22.8.4 — Final Scenario Execution Reliability & Telemetry Acceptance Audit

**Execution Date:** 2026-11-17T01:14:00+05:30  
**Status:** IMPLEMENTATION & SYSTEM VERIFICATION COMPLETE  
**Scenario UI Execution Status:** `NOT TESTED — MANUAL USER VERIFICATION REQUIRED`  
**Safety & Compliance:** DRY_RUN STRICTLY PRESERVED — ZERO CLOUD/HOST/FIREWALL MODIFICATIONS

---

## 1. Executive Summary

Phase 22.8.4 resolves the timeout anomaly observed during manual acceptance testing of Scenario 6 (Brute Force) on the Docker dashboard (`http://localhost:5175`), fixes a secondary machine-to-machine authentication issue on the telemetry sensor auto-ingestion pipeline, implements automated orphaned trigger response reconciliation, and validates persistent PCAP deduplication across sensor restarts.

### Initial Observations & Anomaly Description
During manual scenario execution on `http://localhost:5175`:
- **Scenario 1 (Benign HTTP):** `COMPLETED` in 8,708.05 ms
- **Scenario 2 (Port Scan):** `COMPLETED` in 3,902.68 ms
- **Scenario 3 (Traffic Spike):** `COMPLETED` in 8,708.99 ms
- **Scenario 4 (Suspicious Transfer):** `COMPLETED` in 3,002.89 ms
- **Scenario 5 (Live Containment):** `COMPLETED` in 900.94 ms
- **Scenario 6 (Brute Force):** `TIMED_OUT` in 12,013.15 ms (`Scenario 'brute_force' timed out after 12.0s while actively running in traffic-generator container.`)

---

## 2. Root Cause Analysis — Scenario 6 (Brute Force)

Inspection of `deployment/hybrid-lab/traffic-generator/scenarios/scenario_brute_force.py` (lines 42–54) isolated the exact cause:

```python
for user, pwd in credentials:
    auth_header = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    req = urllib.request.Request(
        f"http://{target_ip}:22/",
        headers={"Authorization": f"Basic {auth_header}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            pass
    except Exception:
        pass
```

1. **Target Port Mismatch:** The target is `10.20.10.40:22` (`cloud-workload`). Port 22 is an SSH/raw TCP socket, not an HTTP daemon.
2. **Deterministic Blocking Delay:** `urllib.request.urlopen` attempts an HTTP exchange. Because the port does not reply with HTTP responses, each call blocks for the entirety of its `timeout=1.0` parameter.
3. **Cumulative Wall-Clock Time:** With 12 credential tuples, $12 \times 1.0\text{s} = 12.0\text{s}$ of socket wait time is mathematically guaranteed.
4. **Packet Generation & Serialization:** Following the HTTP attempts, Scapy constructs 23 TCP SYN/RST packets and writes them via `wrpcap()`.
5. **Total Execution Duration:** The script requires between 12.5 and 13.5 seconds.
6. **Previous Rigid Timeout:** `gateway-api` had an indiscriminate 12.0-second timeout ceiling. It terminated polling at 12.013 seconds—approximately 0.5 to 1.5 seconds before the daemon completed writing the `.res` file.

---

## 3. Late Completion Proof & Orphan Accumulation

Direct container filesystem inspection of `/var/lib/hybrid-lab/telemetry/triggers` revealed two orphaned response files:
- `run_brute_force_53b7a3cb.res`
- `run_brute_force_73b86cfa.res`

Inspection of both files verified:
- `"status": "COMPLETED"`
- `"success": true`
- `"packets_generated": 35`
- Target PCAP: `scenario6_brute_force_onprem_to_cloud.pcap`
- Timestamps showed completion occurred ~1.2 seconds after the frontend reported `TIMED_OUT`.

Because `gateway-api` unlinked the `.run` marker upon timeout, the subsequent `.res` file remained stranded on disk indefinitely.

---

## 4. Architectural Remediations Implemented

### 4.1 Scenario-Specific Timeout Matrix
Rather than indiscriminately inflating timeouts across all scenarios, `backend/app/services/hybrid_traffic_service.py` was updated with tailored, telemetry-driven limits:

| Scenario Key | Measured Runtime | Configured Timeout | Rationale |
|---|---|---|---|
| `containment` | 900.94 ms | **8.0s** | Local TCP probe + 6 SYN packets |
| `suspicious_transfer` | 3,002.89 ms | **10.0s** | Base64 chunked exfiltration |
| `port_scan` | 3,902.68 ms | **10.0s** | Multi-port probe sweeps |
| `benign` | 8,708.05 ms | **15.0s** | Realistic HTTP user traffic pacing |
| `traffic_spike` | 8,708.99 ms | **15.0s** | Burst load emulation |
| `brute_force` | 12,500–13,500 ms | **22.0s** | Safe headroom over the 12s socket delay |
| `all` (suite) | ~38,000 ms | **50.0s** | Sequential execution of all 6 scenarios |

### 4.2 Grace Period & State Lifecycle Reporting
`HybridTrafficService.run_scenario()` now implements:
1. **Active Grace Window:** If the nominal scenario timeout expires while the status is actively `RUNNING`, a 2.0-second grace window is granted to allow `.res` flushing.
2. **State Reporting:**
   - `QUEUED`: Request file placed, daemon not yet executing.
   - `RUNNING`: `.run` marker detected, active container execution.
   - `COMPLETED`: `.res` successfully processed within nominal timeout.
   - `LATE_COMPLETION`: Completed during the grace window or during orphan reconciliation.
   - `FAILED`: Execution returned an error payload.
   - `TIMED_OUT`: Timeout expired with `state_at_timeout` diagnostic detail.
3. **Automated Orphan Sweep:** `reconcile_orphaned_responses()` runs before any scenario execution and during background scans, reconciling any stranded `.res` files into audit logs and unlinking them.

### 4.3 Telemetry Sensor Ingestion & Machine Authentication Fix
`telemetry-sensor` logs previously reported:
`[!] Auto-ingest warning for scenarioX.pcap: HTTP Error 401: Unauthorized`

Root causes & fixes:
1. `backend/app/api/deps.py`: `require_service_or_trusted_network` checks `settings.trusted_management_networks`. Default was loopback-only.
2. `backend/app/config.py`: Added `"10.30.10.0/24"` (the hybrid lab management subnet `mgmt_net`) to trusted defaults.
3. `deployment/hybrid-lab/compose.yaml`: Added `GATEWAY_SERVICE_KEY` environment variable propagation to `telemetry-sensor` and explicit `TRUSTED_MANAGEMENT_NETWORKS: '["127.0.0.1/32","::1/128","10.30.10.0/24"]'` to `gateway-api`.
4. `deployment/hybrid-lab/telemetry/sensor_service.py`: Updated `upload_pcap_to_gateway()` and `ingest_simulated_vpc_flowlogs_to_gateway()` to include `X-Service-Token: <GATEWAY_SERVICE_KEY>` header.

### 4.4 Frontend Support for LATE_COMPLETION
`src/components/SimulationView.tsx` was updated to recognize and style `LATE_COMPLETION` status badges and toast notifications.

---

## 5. Verification & Audit Results

### 5.1 Telemetry Sensor Ingestion & Idempotency
Following recreation and restart of `telemetry-sensor`:
- **First Run (Initial Ingestion):**
  ```text
  [INGEST_SUCCESS] router_live_router_capture_20261103_210158.pcap: flows=4, events_persisted=4
  [INGEST_SUCCESS] scenario1_benign_onprem_to_cloud.pcap: flows=1, events_persisted=1
  [INGEST_SUCCESS] scenario2_port_scan_onprem_to_cloud.pcap: flows=25, events_persisted=25
  [INGEST_SUCCESS] scenario3_traffic_spike_onprem_to_cloud.pcap: flows=1, events_persisted=1
  [INGEST_SUCCESS] scenario4_suspicious_transfer_onprem_to_cloud.pcap: flows=1, events_persisted=1
  [INGEST_SUCCESS] scenario5_blocked_restricted_containment.pcap: flows=27, events_persisted=27
  [INGEST_SUCCESS] scenario6_brute_force_onprem_to_cloud.pcap: flows=1, events_persisted=1
  [+] Startup scan completed. Ingested 7 new/modified PCAPs out of 7 total.
  ```
- **Second Run (Idempotent Restart Verification):**
  ```text
  [IDEMPOTENT_SKIP] router_live_router_capture_20261103_210158.pcap: ALREADY_COMPLETED_IDENTICAL_HASH
  [IDEMPOTENT_SKIP] scenario1_benign_onprem_to_cloud.pcap: ALREADY_COMPLETED_IDENTICAL_HASH
  [IDEMPOTENT_SKIP] scenario2_port_scan_onprem_to_cloud.pcap: ALREADY_COMPLETED_IDENTICAL_HASH
  [IDEMPOTENT_SKIP] scenario3_traffic_spike_onprem_to_cloud.pcap: ALREADY_COMPLETED_IDENTICAL_HASH
  [IDEMPOTENT_SKIP] scenario4_suspicious_transfer_onprem_to_cloud.pcap: ALREADY_COMPLETED_IDENTICAL_HASH
  [IDEMPOTENT_SKIP] scenario5_blocked_restricted_containment.pcap: ALREADY_COMPLETED_IDENTICAL_HASH
  [IDEMPOTENT_SKIP] scenario6_brute_force_onprem_to_cloud.pcap: ALREADY_COMPLETED_IDENTICAL_HASH
  [+] Startup scan completed. Ingested 0 new/modified PCAPs out of 7 total.
  ```
- **Ledger Persistence:** Confirmed at `/var/lib/hybrid-lab/telemetry/metadata/pcap_ingestion_ledger.json` (17,721 bytes).
- **PostgreSQL Events Total:** 4,729 deduplicated records.

### 5.2 Orphan Sweep Verification
Execution of `reconcile_orphaned_responses()` cleanly harvested and deleted the two pre-existing `.res` files:
```text
Reconciled: [
  {'res_file': 'run_brute_force_73b86cfa.res', 'scenario': 'brute_force', 'status': 'COMPLETED'},
  {'res_file': 'run_brute_force_53b7a3cb.res', 'scenario': 'brute_force', 'status': 'COMPLETED'}
]
```
The triggers directory now contains exclusively `.daemon_heartbeat.json`.

### 5.3 Policy Enforcement DRY_RUN Verification
Execution of `iptables -L -n -v` in `lab-router` verified:
- Zero rules were inserted or deleted.
- Zero traffic drops were modified.
- Policy enforcement strictly remains `DRY_RUN`.

### 5.4 Test Suite & Quality Gates
- **Backend Pytest:** **406 / 406 passed** (0 failures, 106 warnings) in 138.68s.
  * Added 3 targeted unit tests in `backend/tests/test_phase22_8_3_simulation_rendering.py`:
    - `test_default_scenario_timeouts_configuration`
    - `test_management_network_trust_10_30_10_0`
    - `test_orphan_res_reconciliation`
- **TypeScript:** `npx tsc -b` passed with 0 errors.
- **Frontend Linter (oxlint):** 0 warnings, 0 errors across 29 files with 116 rules.
- **Vite Production Build:** Compiled in 252ms (`dist/assets/index-BE1lsIoz.js`: 546.73 kB).
- **Standalone Windows Executable Rebuild:**
  * Path: `backend\executable\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe`
  * Size: 37.42 MB (39,241,266 bytes)
  * SHA-256: `A2511F2DC11E60389E724E8472D0FDF89CB079D444C23C2FD6D403EA713DFE99`
  * Build Status: 17/17 pipeline steps verified.

### 5.5 Docker Container Fleet Status
All 13 Docker hybrid-lab containers are running and healthy:
- `hybrid-lab-gateway-api`: Up (healthy) on `0.0.0.0:8001->8000/tcp`
- `hybrid-lab-frontend`: Up (healthy) on `0.0.0.0:5175->80/tcp`
- `hybrid-lab-telemetry-sensor`: Up (idempotent, auto-ingesting)
- `hybrid-lab-traffic-generator`: Up (daemon active, heartbeat online)
- `hybrid-lab-router`: Up (healthy, DRY_RUN)
- `hybrid-lab-postgres`: Up (healthy)
- Workloads & clients (`cloud-workload`, `cloud-web`, `cloud-db`, `cloud-client`, `onprem-workload`, `onprem-web`, `onprem-client`): All Up (healthy)

---

## 6. Manual Verification Instructions for User

Because agent policy strictly prohibits automated browser actions or direct port probing against localhost:

1. Open your browser and navigate to the Docker dashboard at:
   `http://localhost:5175`
2. Navigate to **Attack Simulation** from the left navigation sidebar.
3. Locate Card 6: **Scenario 6 — Brute Force (SSH/HTTP)**.
4. Click **Launch Scenario**.
5. Observe the execution indicator:
   - Notice that the scenario executes past 12.0s without timing out.
   - At approximately 13.0–14.5s, the card will report **COMPLETED** (or **LATE_COMPLETION** if within the grace window).
   - The status badge will show green (`#4ade80`).
   - Telemetry will show 35 packets captured in `scenario6_brute_force_onprem_to_cloud.pcap`.
6. (Optional) Click **Run Full Benchmark Suite** to execute all 6 scenarios sequentially (governed by the 50.0s suite timeout).
