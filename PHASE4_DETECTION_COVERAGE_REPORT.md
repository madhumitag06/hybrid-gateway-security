# PHASE 4: DETECTION COVERAGE AND DOMAIN GENERALIZATION REPORT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** Phase 4 — Detection Coverage Hardening and Generalization Analysis  
**Date:** November 2026  
**Artifacts Evaluated:** `data/reports/model_v2_comparison_report.json`, `data/reports/leave_one_dataset_out_report.json`, `data/reports/domain_shift_report.json`, `data/reports/live_scenario_validation_report.json`  

---

## 1. Executive Summary

Phase 4 conducted an exhaustive investigation into the detection coverage, generalization limits, and failure modes of the machine-learning threat detection models across five standardized traffic categories:
1. `BENIGN`
2. `PORT_SCAN`
3. `BRUTE_FORCE`
4. `TRAFFIC_SPIKE`
5. `SUSPICIOUS_TRANSFER`

Our investigation compared the active **Production Random Forest** model (`ml/models/model.joblib`, trained on synthetic distributions with 10 features) against the candidate **Big Data XGBoost V2** model (`ml/models/candidates/bigdata_v2/`, trained on 6.49 million multi-dataset records with 9 features) across both standardized enterprise datasets and live hybrid-cloud Docker lab scenarios.

### Core Empirical Findings:
- **Production Baseline RF Failure on Real Data:** When tested against real-world network traffic, the legacy synthetic Random Forest achieves only **57.23% accuracy** and suffers an unacceptably high **False Negative Rate of 74.90%**, missing almost three-quarters of real-world attacks.
- **Candidate XGBoost V2 Superiority:** The clean 9-feature Big Data XGBoost V2 model achieves **98.42% accuracy**, a **Macro F1 score of 0.9486**, an attack **False Negative Rate of 2.51%**, and a **False Positive Rate of 0.96%**.
- **Domain Shift Bottlenecks Identified:** In strict Leave-One-Dataset-Out (LODO) testing, models trained strictly on TCP/HTTP attacks experience near-total failure (1.21% accuracy) when tested on pure UDP reflection amplification attacks (CIC-DDoS2019), proving that multi-dataset pooling is mathematically necessary for hybrid cloud perimeter defense.

---

## 2. In-Depth Attack Category Weakness Analysis

### 2.1 UDP Reflection / Amplification DDoS Attacks

#### Vulnerability Analysis:
Network reflection and amplification attacks utilize stateless UDP services with high amplification factors:
- **DNS (UDP 53):** Amplification factor 28x to 54x (EDNS0 queries).
- **NTP (UDP 123):** Amplification factor up to 556x (`monlist` command).
- **SSDP (UDP 1900):** Amplification factor 30x (M-SEARCH queries).
- **MSSQL (UDP 1434):** Amplification factor 25x (`MC-SQLR` ping).
- **NetBIOS (UDP 137):** Amplification factor 3.8x (Name service status).
- **LDAP (UDP 389):** Amplification factor 46x to 55x (CLDAP ping requests).
- **SNMP (UDP 161):** Amplification factor 6.3x (`GetBulkRequest`).
- **TFTP (UDP 69):** Amplification factor 60x.

#### Why Legacy Models and Single-Source Models Fail:
1. **Asymmetric Flow Characteristics:**  
   Unlike TCP sessions where flow features exhibit bidirectional SYN/ACK handshakes and balanced sequence numbers, UDP amplification attacks generate high-volume incoming streams (`packets_per_sec > 10,000`, `bytes_per_sec > 10,000,000`) with tiny, uniform request packets (`avg_packet_size < 100 bytes`).
2. **Port Blind Spots in Legacy Datasets:**  
   Legacy intrusion detection datasets (e.g., CIC-IDS2017) focused almost exclusively on TCP port 80/443 floods (Slowloris, Slowhttptest, Hulk, GoldenEye). A model trained without UDP reflection samples misclassifies high-rate UDP streams as benign streaming media or DNS background traffic.
3. **Mitigation in XGBoost V2:**  
   By incorporating CIC-DDoS2019 into the pooled multi-dataset training corpus, XGBoost V2 learned split conditions on `packets_per_sec`, `bytes_per_sec`, and `avg_packet_size` that correctly isolate UDP reflection floods across ephemeral and administrative ports with **99.9% precision**.

---

### 2.2 Suspicious Transfer vs. Legitimate High-Volume API Traffic

#### Vulnerability Analysis:
A major failure mode of synthetic ML models is classifying any large data transfer or any session on non-standard HTTP ports (e.g., `8443`, `8080`, `9000`) as data exfiltration (`SUSPICIOUS_TRANSFER`).

#### Empirical Evidence from Live Lab Scenario 4:
- In Scenario 4, a client transferred **320 KB over 22.0 seconds** to port `8443` at an average rate of **14.6 KB/s** (240 packets).
- **Production Baseline RF Verdict:** Flagged as `SUSPICIOUS_TRANSFER` with **Confidence 0.780** and **Risk Score 78**, recommending an intrusive `MONITOR` or `RESTRICT` policy.
- **Candidate XGBoost V2 Verdict:** Flagged as `BENIGN` with **Confidence 0.963** and **Risk Score 4**.

#### Root Cause & Feature Dissection:
- Synthetic training data contained an artificial heuristic where payloads $>200\text{ KB}$ on port $8443$ were labeled malicious.
- Real enterprise hybrid networks regularly transfer multi-megabyte payloads over TLS REST APIs, database syncs, and microservice RPCs.
- In XGBoost V2, the decision trees split on `byte_rate` ($14,618\text{ bytes/s}$) and `duration` ($22.0\text{ s}$), recognizing that low-rate steady-state transfers represent valid client-server interactions. Genuine exfiltration attacks typically display burst rates exceeding $1\text{ MB/s}$ or off-hours anomalous volume.

---

### 2.3 Traffic Spikes: Benign Bursts vs. Volumetric Flood Disagreements

#### Vulnerability Analysis:
Differentiating between an organic spike in legitimate user activity (e.g., a burst of page asset downloads) and an active Denial-of-Service volumetric flood is critical to avoiding service disruption.

#### Empirical Evidence from Live Lab Scenario 3:
- In Scenario 3, a web client fetched a **1.2 MB web payload in 3.01 seconds** over HTTP port 80 (**1,200 packets**, **398.7 pkts/s**, **403.8 KB/s**).
- **Production Baseline RF Verdict:** Flagged as `TRAFFIC_SPIKE` with **Confidence 1.000** and **Risk Score 100**, triggering an active `RESTRICT` rate limit.
- **Candidate XGBoost V2 Verdict:** Flagged as `BENIGN` with **Confidence 0.999** and **Risk Score 0**.

#### Root Cause:
- The legacy Random Forest had a hard synthetic split at `packet_count > 1000`, causing immediate false alarms on any file download exceeding 1 MB.
- In contrast, real DDoS floods in CIC-DDoS2019 and CSE-CIC-IDS2018 exhibit packet rates of $10,000\text{ to }100,000\text{ pkts/sec}$. A client pulling 400 KB/s on port 80 with standard TCP MTU (`avg_packet_size = 1013 bytes`) is completely benign web delivery.
- XGBoost V2 eliminates this false positive, preventing accidental throttling of legitimate business users.

---

### 2.4 SSH Brute-Force & Credential Stuffing Telemetry Limitations

#### Vulnerability Analysis:
In modern encrypted protocols (SSHv2, TLS 1.3), authentication attempts occur within encrypted session payloads. At Layer 3 and Layer 4:
- An isolated failed authentication attempt consists of a standard TCP 3-way handshake followed by a 25–35 packet key exchange and SSH banner negotiation (approx. 2,500–4,500 bytes).
- A valid interactive login or SSH public-key connection displays nearly identical packet counts and byte sizes during inception.
- Prior audits revealed that legacy models relied on an artificial `failed_auth_count` feature (accounting for 55.46% of model importance) that was impossible to extract from live network packets without decrypting the SSH stream or parsing host auth logs.

#### Architectural Defense-in-Depth Solution:
1. **Model Hygiene:**  
   `failed_auth_count` was completely eliminated in Feature Schema V2.
2. **Stateful Connection Tracking (`SSHProbeTracker`):**  
   The gateway delegates credential stuffing containment to `SSHProbeTracker` in `PolicyEngine`, which maintains a rolling 60-second sliding window of SSH connection bursts per source IP:
   - If `byte_count > 10,000` (established interactive session or SFTP file transfer), the flow is classified as valid session activity and does NOT increment probe counts.
   - For rapid small-session connections ($<10\text{ KB}$):
     - **$\ge 3$ probes:** Escalates to `MONITOR`.
     - **$\ge 6$ probes:** Escalates to `RESTRICT` (port 22 targeted drop).
     - **$\ge 12$ probes:** Escalates to `BLOCK` (immediate host-wide quarantine).
3. **Safety Guarantee:**  
   The gateway does not claim authentication-level visibility without genuine host auth logs; instead, it enforces verifiable network-level connection burst rate boundaries.

---

## 3. Comprehensive Performance Comparison Matrix

The five model architectures were evaluated on identical stratified test partitions (**99,997 samples**) from the cleaned 6.49M record pool:

| Metric | Production RF (Synthetic) | Big Data XGBoost V1 (Zero-Auth) | Big Data XGBoost V2 (Clean 9) | Big Data RF V2 (Clean 9) | Big Data LightGBM V2 (Clean 9) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Feature Schema** | 10 Features (Synthetic) | 10 Features (Zeroed Auth) | **9 Features (Clean V2)** | 9 Features (Clean V2) | 9 Features (Clean V2) |
| **Accuracy** | 57.23% | 96.12% | **98.42%** | 98.33% | 93.39% |
| **Macro Precision** | 0.1928 | 0.8124 | **0.9548** | 0.9412 | 0.7812 |
| **Macro Recall** | 0.3596 | 0.6982 | **0.9429** | 0.9205 | 0.6431 |
| **Macro F1 Score** | 0.1871 | 0.7340 | **0.9486** | 0.9301 | 0.6728 |
| **Weighted F1 Score** | 0.4993 | 0.9610 | **0.9842** | 0.9831 | 0.9312 |
| **False Positive Rate** | 14.48% | 2.36% | **0.96%** | **0.89%** | 6.04% |
| **False Negative Rate** | 74.90% | 6.40% | **2.51%** | 2.92% | 2.99% |
| **Single-Flow Latency** | 20.73 ms | 1.12 ms | **0.897 ms** | 18.42 ms | 1.05 ms |
| **P95 Latency** | 30.63 ms | 1.45 ms | **1.10 ms** | 26.50 ms | 1.32 ms |
| **Batch Throughput** | 226,671 fps | 480,120 fps | **507,372 fps** | 240,110 fps | 495,200 fps |
| **Model Size** | 1.14 MB | 2.28 MB | 2.29 MB | 14.20 MB | 1.85 MB |

---

## 4. Phase 4 Conclusion & Transition to Phase 5

1. **Production Random Forest Is Unviable for Real Attacks:**  
   The synthetic Random Forest's 74.9% False Negative Rate and 14.48% False Positive Rate on real data prove it cannot remain the long-term defense engine.
2. **XGBoost V2 Meets All Detection Criteria:**  
   XGBoost V2 achieves near-perfect multi-class discrimination (Macro F1: 0.9486, Accuracy: 98.42%), resolves false positives on large transfers and web spikes, and processes flows in sub-millisecond time (**0.897 ms**).
3. **Recommendation for Phase 5:**  
   Proceed to **Controlled Model Promotion and Rollback** (Phase 5) to establish XGBoost V2 as the primary authoritative engine while retaining the Random Forest model as a standby rollback mechanism.

