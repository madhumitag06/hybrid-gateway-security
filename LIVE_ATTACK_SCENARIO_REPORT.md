# Live Hybrid-Cloud Attack Scenario and Traffic Ingestion Report (Phase 3)

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** Phase 3 — Live Hybrid-Cloud Gateway Integration and XGBoost V2 Validation  
**Date:** November 2026  
**Status:** 6 Scenarios Executed, Captured, Evaluated & Persisted

---

## Executive Summary

To evaluate how the **authoritative production Random Forest** and the **candidate Big Data XGBoost V2** behave when processing real network packets traversing a hybrid-cloud boundary, all six controlled traffic scenarios were executed across the live Docker virtual hybrid-lab infrastructure.

Network traffic originated from on-premises workloads (`10.10.10.0/24`), traversed the central transit router (`10.10.10.2 -> 10.20.10.2`), and targeted simulated AWS VPC cloud services (`10.20.10.0/24`). Traffic was captured into PCAP captures, ingested through `FlowAggregator`, evaluated simultaneously by both models, and persisted into PostgreSQL (`security_events` and `shadow_predictions`).

---

## 1. Hybrid-Cloud Testbed Topology

```
+-----------------------------------------------------------------------------------+
| ON-PREMISES SUBNET (10.10.10.0/24)                                                |
|  - onprem-client:   10.10.10.10 (Employee Workstation)                            |
|  - onprem-web:      10.10.10.20 (Enterprise Portal)                              |
|  - onprem-workload: 10.10.10.30 (Batch Integration Server)                        |
|  - traffic-gen:     10.10.10.50 (Controlled Scenario Traffic Generator)           |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼ (eth0: 10.10.10.2)
+-----------------------------------------------------------------------------------+
| HYBRID TRANSIT GATEWAY: hybrid-lab-router (10.10.10.2 / 10.20.10.2 / 10.30.10.2) |
|  - Netfilter / iptables router kernel enforcement                                  |
|  - Telemetry sensor packet capture & flow logging                                 |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼ (eth1: 10.20.10.2)
+-----------------------------------------------------------------------------------+
| SIMULATED AWS VPC SUBNET (10.20.10.0/24 - us-east-1)                              |
|  - cloud-client:   10.20.10.10 (VPC Worker Instance)                              |
|  - cloud-web:      10.20.10.20 (VPC Web Application, Port 80, 443)                |
|  - cloud-db:       10.20.10.30 (VPC Database, Port 5432, 3306)                    |
|  - cloud-workload: 10.20.10.40 (Compute/Storage, Port 22, 2222, 8443)             |
+-----------------------------------------------------------------------------------+
```

---

## 2. Multi-Scenario Empirical Evaluation Matrix

| Scenario ID | Traffic Description | PCAP File | Total Packets | Aggregated Flows | Production RF (Authoritative) | Candidate XGBoost V2 (Advisory) | Agreement Rate | Avg Prod Latency | Avg Cand Latency |
|:---:|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **A** | Benign On-Prem to Cloud HTTPS | `scenario1_benign...pcap` | 25 | 1 | **BENIGN** (Risk: 0, 99.9%) | **BENIGN** (Risk: 0, 99.8%) | **100.0%** (1/1) | 250.13 ms | 2.08 ms |
| **B** | Port Scan Across Gateway | `scenario2_port_scan...pcap` | 50 | 25 | **PORT_SCAN** (Risk: 91, 81.1%) | **PORT_SCAN** (Risk: 91, 64.7%) | **96.0%** (24/25) | 95.47 ms | 1.95 ms |
| **C** | SSH Brute-Force Probes | `scenario6_brute_force...pcap`| 35 | 1 | **BENIGN** (Risk: 15, 61.5%) | **BENIGN** (Risk: 8, 80.3%) | **100.0%** (1/1) | 47.89 ms | 1.96 ms |
| **D** | Volumetric HTTP Traffic Spike | `scenario3_traffic_spike...` | 1,200 | 1 | **TRAFFIC_SPIKE** (Risk: 100, 100%)| **BENIGN** (Risk: 0, 99.8%) | **0.0%** (0/1) | 44.75 ms | 1.37 ms |
| **E** | Suspicious File Transfer | `scenario4_suspicious...pcap` | 240 | 1 | **SUSPICIOUS_TRANSFER** (Risk: 78) | **BENIGN** (Risk: 4, 88.6%) | **0.0%** (0/1) | 70.33 ms | 1.77 ms |
| **F** | Quarantine & Containment | `scenario5_containment...pcap`| 54 | 27 | **PORT_SCAN** (Risk: 91, 81.1%) | **PORT_SCAN** (Risk: 91, 64.7%) | **96.3%** (26/27) | 62.85 ms | 2.00 ms |

---

## 3. Detailed Scenario Audits and Flow Evidence

### Scenario A: Normal On-Premises to Cloud Web Traffic
- **Endpoints:** `10.10.10.10 -> 10.20.10.20:443` (TCP)
- **Extracted V2 Features:** `packet_count=25`, `byte_count=13,760`, `duration=2.45s`, `conn_rate=9.58 pps`, `dst_port=443`, `unique_dst_ports=1`, `bytes_per_sec=5,616 B/s`, `packets_per_sec=10.2 pps`, `avg_packet_size=550.4 B`.
- **Production Prediction:** `BENIGN` (Risk Score: 0, Confidence: 0.9995).
- **Candidate Shadow Prediction:** `BENIGN` (Risk Score: 0, Confidence: 0.9977).
- **Agreement:** **TRUE (100% Concordance)**.
- **Enforcement Decision:** `Allow` (No firewall rule created).

### Scenario B: Horizontal Multi-Port Sweep Across Hybrid Boundary
- **Endpoints:** `10.10.10.50 -> 10.20.10.40` (Probing 25 sequential TCP ports: 21, 22, 23, 25, 53, 80, 110, etc.)
- **Extracted V2 Features (per probe):** `packet_count=2`, `byte_count=80`, `duration=0.0s`, `conn_rate=208.33 pps`, `unique_dst_ports=25`, `avg_packet_size=40.0 B`.
- **Production Prediction:** `PORT_SCAN` across 25 flows (Risk Score: 91, Confidence: 0.811).
- **Candidate Shadow Prediction:** `PORT_SCAN` across 24 flows (Risk Score: 91, Confidence: 0.647).
- **Agreement:** **96.0% (24 / 25 concordant)**.
- **Top SHAP Attribution (Candidate):** `unique_dst_ports (25.0)` contributed $+5.312$ SHAP log-odds ($+531.2\%$ increase in `PORT_SCAN` probability).
- **Enforcement Decision:** `Block` via `PolicyEngine` (`RECON_PORT_SCAN_QUARANTINE`).

### Scenario C: SSH Credential Brute-Force Probes
- **Endpoints:** `10.10.10.50 -> 10.20.10.40:22` (TCP)
- **Extracted V2 Features:** `packet_count=35`, `byte_count=8,487`, `duration=1.8s`, `conn_rate=19.44 pps`, `dst_port=22`, `unique_dst_ports=1`.
- **Production Prediction:** `BENIGN` (Risk Score: 15, Confidence: 0.615).
- **Candidate Shadow Prediction:** `BENIGN` (Risk Score: 8, Confidence: 0.803).
- **Agreement:** **TRUE (Concordant on Benign)**.
- **Analysis:** A single isolated SSH connection consisting of 35 packets and 8.4 KB cannot be determined as malicious from L3/L4 packet headers alone. However, repeated connection bursts trigger the `SSHProbeTracker` safeguard in `PolicyEngine`, which escalates containment from `Monitor` (at 3 probes) to `Restrict` (at 6 probes) to `Block` (at 12 probes).

### Scenario D: High-Volume HTTP Traffic Burst
- **Endpoints:** `10.10.10.50 -> 10.20.10.40:80` (TCP)
- **Extracted V2 Features:** `packet_count=1,200`, `byte_count=1,197,600` (1.2 MB), `duration=3.0s`, `conn_rate=400.33 pps`, `dst_port=80`, `bytes_per_sec=399,533 B/s`, `packets_per_sec=400.33 pps`, `avg_packet_size=998.0 B`.
- **Production Prediction:** `TRAFFIC_SPIKE` (Risk Score: 100, Confidence: 1.000).
- **Candidate Shadow Prediction:** `BENIGN` (Risk Score: 0, Confidence: 0.998).
- **Agreement:** **FALSE (Disagreement: `TRAFFIC_SPIKE_vs_BENIGN`)**.
- **Root Cause:** In the production RF's synthetic training data, any transfer exceeding 1,000 packets was synthetically labeled an attack. In contrast, XGBoost V2 was trained on real enterprise datasets where 1.2 MB web transfers at 400 KB/s are standard baseline traffic. In real volumetric floods, throughput exceeds 10–100 MB/s and 10,000+ pps.

### Scenario E: High-Volume Suspicious Transfer
- **Endpoints:** `10.10.10.30 -> 10.20.10.40:8443` (TCP)
- **Extracted V2 Features:** `packet_count=240`, `byte_count=321,120` (321 KB), `duration=21.89s`, `dst_port=8443`, `bytes_per_sec=14,668 B/s` (14.6 KB/s), `avg_packet_size=1,338 B`.
- **Production Prediction:** `SUSPICIOUS_TRANSFER` (Risk Score: 78, Confidence: 0.576).
- **Candidate Shadow Prediction:** `BENIGN` (Risk Score: 4, Confidence: 0.886).
- **Agreement:** **FALSE (Disagreement: `SUSPICIOUS_TRANSFER_vs_BENIGN`)**.
- **Root Cause:** A 321 KB transfer over 22 seconds on HTTPS port 8443 represents an average throughput of just 14.6 KB/s. Network flow statistics alone without decrypted payload inspection cannot differentiate a 320 KB API request from data exfiltration.

### Scenario F: Boundary Quarantine and Port Containment
- **Endpoints:** `10.10.10.50 -> 10.20.10.30` (Probing 27 ports on Database server)
- **Extracted V2 Features:** `packet_count=2`, `byte_count=80`, `unique_dst_ports=27`.
- **Production Prediction:** `PORT_SCAN` across 27 flows (Risk Score: 91).
- **Candidate Shadow Prediction:** `PORT_SCAN` across 26 flows (Risk Score: 91).
- **Agreement:** **96.3% (26 / 27 concordant)**.
- **Enforcement Result:** Lab router injected a drop rule for `10.10.10.50`. Subsequent connection attempts to `10.20.10.30` were dropped at the packet filter.

