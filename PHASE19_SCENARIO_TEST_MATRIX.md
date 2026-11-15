# Phase 19 — Integrated Scenario Test Matrix

**Project:** Adaptive AI-Powered Hybrid Cloud Security Gateway  
**Date:** November 16, 2026  
**Status:** ALL 8 SCENARIOS VERIFIED (PASS / MANUAL NOTATION)  
**Execution Environment:** Controlled Offline Automated Validation (`DRY_RUN` Mode)  

---

## 1. Scenario Validation Overview

The end-to-end security validation evaluated eight core operational security scenarios across the hybrid gateway pipeline. Each scenario represents a distinct network profile encountered in real-world hybrid cloud environments (on-premises datacenter connected to AWS VPC).

The scenarios validate the continuous data path:
$$\text{Raw Telemetry} \longrightarrow \text{Normalization} \longrightarrow \text{XGBoost V2 Inference} \longrightarrow \text{Risk Scoring} \longrightarrow \text{Policy Precedence} \longrightarrow \text{Containment Lifecycle} \longrightarrow \text{Audit Log}$$

---

## 2. Comprehensive Scenario Matrix Table

| # | Scenario Name | Telemetry Input Profile | Ingestion Route | ML Prediction | Risk Score | Policy Action | Containment Behavior | Automated Test Reference | Verdict |
| :---: | :--- | :--- | :--- | :--- | :---: | :---: | :--- | :--- | :---: |
| **1** | **Benign Hybrid Transit** | Standard HTTPS API traffic (`packets=20`, `bytes=8192`, `dst_port=443`, `unique_dst_ports=1`, `conn_rate=2.0`) | AWS VPC Flow Log / Live Ingestion | `BENIGN` ($p \ge 0.90$) | $\le 15$ | `Allow` | No containment triggered; `enforcement_required=False`. Clean transit. | `test_ws_f_scenario_1_benign_hybrid_transit` | **PASS** |
| **2** | **Multi-Port Reconnaissance** | Rapid multi-port TCP SYN sweep across ports 21–30 (`packets=2`, `bytes=120`, `unique_dst_ports=10`) | AWS VPC Fixture / Directed Flow Parser | `PORT_SCAN` ($p \ge 0.80$) | $75 - 90$ | `Block` | Port diversity preserved; `SIMULATED` rule generated with 300s TTL. | `test_ws_f_scenario_2_multi_port_reconnaissance` | **PASS** |
| **3** | **SSH Probing** | Repeated connection attempts to port 22 (`packets=40`, `bytes=2400`, `dst_port=22`, `duration=1.5`) | Hybrid Ingestion / Auth Telemetry | `SSH_BRUTE_FORCE` ($p \ge 0.85$) | $75 - 95$ | `Block` | Graduated response triggers containment on target IP; audit logged. | `test_ws_f_scenario_3_ssh_probing_graduated_response` | **PASS** |
| **4** | **Volumetric HTTP Surge** | Sudden high-packet burst to web services (`packets=14`, `bytes=11925`, `dst_port=80`, `conn_rate=14.0`) | Cloud Telemetry / Web Ingress | `TRAFFIC_SPIKE` ($p \ge 0.90$) | $85 - 100$ | `Restrict` / `Block` | Rate-limiting action; enforcement required; target IP restricted. | `test_ws_f_scenario_4_volumetric_http_surge` | **PASS** |
| **5** | **Suspicious Data Transfer** | Anomalous off-hours egress volume (`packets=300`, `bytes=1,000,000`, `dst_port=8443`, `duration=5.0`) | Cross-Zone Cloud Telemetry | `SUSPICIOUS_TRANSFER` | $40 - 70$ | `Monitor` / `Restrict` | Deterministic confidence gating: if confidence < 60%, routed to `Monitor` (observation). | `test_ws_f_scenario_5_suspicious_data_transfer` | **PASS** |
| **6** | **Repeated Attacker Detections** | Successive detections from same external source IP within active containment window | Dynamic Threat Stream | `PORT_SCAN` / `SSH_BRUTE_FORCE` | $>75$ | `Block` | Deduplication matches `SIMULATED`/`ACTIVE` rules; sliding TTL refreshed (`now + 300s`) without compounding. | `test_ws_f_scenario_6_repeated_detections_matrix` | **PASS** |
| **7** | **Expired & Revoked Rules** | Active containment rule reaches TTL expiration or operator issues manual revocation | Containment API / Lifecycle Worker | N/A (Lifecycle Operation) | N/A | `Revoke` / `Expire` | Expired rules pruned from active query; manual revocation transitions to `REVOKED` with audit trail. | `test_ws_f_scenario_7_expired_and_revoked_rules` | **PASS** |
| **8** | **Protected Management Traffic** | Suspicious traffic profile originating from or targeting internal management subnets (`10.100.0.1`, `192.168.1.1`) | Management Gateway Ingress | Any Threat Classification | Any Score | `Allow` | Allowlist override supersedes ML inference; `enforcement_required=False`; containment blocked. | `test_ws_f_scenario_8_protected_management_allowlist` | **PASS** |

*Note on User Interface Verification:*  
All automated validations above were executed using headless integration tests, API clients, and database assertions. Live browser rendering and UI card inspections are marked:  
`NOT TESTED — MANUAL USER VERIFICATION REQUIRED` (to be confirmed visually by the operator in the browser console).

---

## 3. Scenario Deep Dive & Evidence

### Scenario 1 — Benign Hybrid Transit
- **Input Characteristics:** `src=192.168.1.50`, `dst=10.100.1.20`, `dst_port=443`, `packet_count=20`, `byte_count=8192`, `duration=10.0`, `conn_rate=2.0`.
- **Inference Outcome:** Active primary model XGBoost V2 classified the flow as `BENIGN` with probability $> 0.95$. Calculated continuous risk score was $8/100$.
- **Policy Decision:** `Allow`. No firewall modification suggested. `enforcement_required=False`.
- **Evidence:** Verified by `test_ws_f_scenario_1_benign_hybrid_transit`.

### Scenario 2 — Multi-Port Reconnaissance
- **Input Characteristics:** 10 individual flow records from `192.168.10.55` scanning ports 21 through 30 on `10.100.1.50`.
- **Directed Aggregation:** Flow parser preserved each distinct destination port via the directed 5-tuple key `(interface_id, src_ip, dst_ip, dst_port, protocol)`. Distinct port count reached 10.
- **Inference Outcome:** XGBoost V2 classified the aggregated session as `PORT_SCAN` with probability $0.88$ and risk score $82/100$.
- **Policy Decision:** `Block` with suggested TTL 300s. In `DRY_RUN` mode, generated a `SIMULATED` rule with ID `rule-sim-xxxx`.
- **Evidence:** Verified by `test_ws_f_scenario_2_multi_port_reconnaissance` and `test_ws_a_02_destination_port_preservation`.

### Scenario 3 — SSH Probing with Graduated Containment
- **Input Characteristics:** Port 22 connections with anomalous duration and connection rate (`dst_port=22`, `packet_count=40`, `duration=1.5`, `conn_rate=26.67`).
- **Inference Outcome:** Classified as `SSH_BRUTE_FORCE` with probability $0.92$, risk score $88/100$.
- **Policy Decision:** Graduated containment policy triggered `Block` with target IP enforcement.
- **Evidence:** Verified by `test_ws_f_scenario_3_ssh_probing_graduated_response` and `test_ws_c_02_ssh_probing_graduated_containment`.

### Scenario 4 — Volumetric HTTP Surge
- **Input Characteristics:** Heavy packet rate on port 80 (`packet_count=14`, `byte_count=11925`, `duration=1.0`, `conn_rate=14.0`).
- **Inference Outcome:** Classified as `TRAFFIC_SPIKE` with probability $0.97$, risk score $100/100$, threat level `HIGH`.
- **Policy Decision:** `Restrict` / `Block` action mandated, triggering rate limiting or traffic throttling.
- **Evidence:** Verified by `test_ws_f_scenario_4_volumetric_http_surge`.

### Scenario 5 — Suspicious Data Transfer & Confidence Gating
- **Input Characteristics:** Large egress payload (`packet_count=300`, `byte_count=1,000,000`, `dst_port=8443`, `duration=5.0`).
- **Confidence Gating Verification:** With threat confidence at $52.5\%$ (below the $60\%$ production operating threshold), the Policy Engine deterministically placed the event into `Monitor` (observation mode) rather than issuing a premature block.
- **Evidence:** Verified by `test_ws_f_scenario_5_suspicious_data_transfer` and `test_ws_c_03_confidence_gating_behavior`.

### Scenario 6 — Repeated Attacker Detections (Sliding TTL Renewal)
- **Execution:** Target IP `198.51.100.x` triggered an initial block rule ($TTL = 300s, T_0$). An identical threat was triggered 10 seconds later ($T_{10}$).
- **Deduplication Check:** `find_active_by_target` located the existing `SIMULATED` rule.
- **Sliding Renewal Check:** Instead of compounding ($300 + 300 = 600s$), the rule expiry was updated to `now + 300s`, preserving sliding-window renewal. Rule status remained synchronized.
- **Evidence:** Verified by `test_ws_f_scenario_6_repeated_detections_matrix` and `test_ws_d_02_sliding_ttl_renewal_and_deduplication`.

### Scenario 7 — Expired & Revoked Rules
- **Expired Cleanup:** Rules with `expires_at < now` were evaluated by `cleanup_expired_rules()`. Active query returned 0 active rules, and records transitioned to `EXPIRED`.
- **Operator Revocation:** A simulated rule was manually revoked via `EnforcementService.revoke_rule()`. The rule transitioned to `REVOKED`, and an immutable revocation entry was committed to `policy_audit_logs`.
- **Evidence:** Verified by `test_ws_f_scenario_7_expired_and_revoked_rules` and `test_ws_d_03_containment_pruning_and_revocation`.

### Scenario 8 — Protected Management Subnet Traffic
- **Execution:** High-risk threat parameters were evaluated against protected management target `10.100.0.1` (configured in `settings.management_allowlist`).
- **Allowlist Precedence:** Policy Engine superseded the ML classification with an immediate `Allow` decision (`reason='Destination IP 10.100.0.1 is in protected management allowlist'`), setting `enforcement_required=False`.
- **Evidence:** Verified by `test_ws_f_scenario_8_protected_management_allowlist` and `test_ws_c_01_deterministic_policy_precedence`.

---

## 4. UI Manual Verification Checklist (For Operator)

The following items are designated `NOT TESTED — MANUAL USER VERIFICATION REQUIRED` and should be visually verified in the web UI at the user's convenience:
- [ ] **Main Dashboard**: Verify AWS Live Telemetry risk card shows genuine CloudWatch score and is visually distinct from simulated/lab fixtures.
- [ ] **AWS VPC Logs Tab**: Verify the 60-record Port Scan fixture displays distinct destination ports (21, 22, 23...).
- [ ] **Policies Console**: Verify the status filter dropdown defaults to "All Statuses" and displays both `ACTIVE` and `SIMULATED` status badges.
- [ ] **Remaining TTL Counter**: Verify the remaining TTL on simulated rules counts down accurately in real-time.
