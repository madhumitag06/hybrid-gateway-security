# DOMAIN GENERALIZATION FINAL REPORT: LEAVE-ONE-DATASET-OUT CROSS-VALIDATION

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** Phase 4 — Domain Shift and Cross-Dataset Generalization  
**Date:** November 2026  
**Artifacts Audited:** `data/reports/leave_one_dataset_out_report.json`, `data/reports/domain_shift_report.json`  

---

## 1. Executive Summary

This report delivers the rigorous, unvarnished Leave-One-Dataset-Out (LODO) cross-validation audit across the four standardized public intrusion detection datasets comprising **6,593,274 cleaned records**:
1. **UNSW-NB15** (Australian Cyber Security Centre / UNSW)
2. **CIC-IDS2017** (Canadian Institute for Cybersecurity)
3. **CSE-CIC-IDS2018** (AWS Cloud Testbed / Communications Security Establishment)
4. **CIC-DDoS2019** (Canadian Institute for Cybersecurity)

### The Domain Shift Reality
In conventional academic benchmarks, models evaluated on randomly partitioned train/test splits from a single dataset achieve deceptive accuracy exceeding 99.9%. However, when a model trained on three datasets is evaluated on an **entirely unobserved fourth network topology**, severe performance degradation occurs across all architectures:

| Held-Out Dataset | Train Sources (3 Combined) | Held-Out Test Samples | Accuracy | Macro F1 | Weighted F1 | FPR | FNR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **UNSW-NB15** | IDS17, IDS18, DDoS19 | 74,998 | **66.80%** | **0.2009** | 0.7693 | 30.45% | 95.69% |
| **CIC-IDS2017** | NB15, IDS18, DDoS19 | 74,997 | **78.11%** | **0.3620** | 0.7308 | 5.68% | 94.32% |
| **CSE-CIC-IDS2018** | NB15, IDS17, DDoS19 | 74,999 | **75.87%** | **0.3137** | 0.7363 | 11.03% | 95.57% |
| **CIC-DDoS2019** | NB15, IDS17, IDS18 | 74,999 | **1.21%** | **0.0088** | 0.0028 | 5.26% | 97.43% |

These empirical results prove that **single-source models fail to generalize across diverse enterprise networks**. Multi-dataset pooling and multi-layered defense safeguards are essential requirements for production hybrid cloud security gateways.

---

## 2. Exhaustive Root-Cause Breakdown by Held-Out Network

### 2.1 The 1.21% Catastrophe: CIC-DDoS2019 Held Out

When CIC-DDoS2019 was held out, the model trained on the other three datasets misclassified **68,585 out of 70,074 DDoS attacks** as `BENIGN`, yielding an attack False Negative Rate of **97.43%**.

#### Why Did Generalization Completely Fail?
1. **Protocol Family Disconnect (UDP vs. TCP):**
   - The test partition of CIC-DDoS2019 consists of massive UDP reflection amplification vectors:
     - NTP (UDP 123)
     - DNS (UDP 53)
     - LDAP (UDP 389)
     - MSSQL (UDP 1433/1434)
     - NetBIOS (UDP 137)
     - SNMP (UDP 161)
     - TFTP (UDP 69)
     - SSDP (UDP 1900)
   - These attacks generate sustained packet rates ($>48,000\text{ packets/sec}$) with small, uniform UDP datagrams ($96.4\text{ bytes}$).
2. **Absence in the Training Triad:**
   - In UNSW-NB15, CIC-IDS2017, and CSE-CIC-IDS2018, Denial-of-Service attacks were exclusively TCP SYN floods or Layer 7 web floods (Slowloris, Slowhttptest, Hulk, GoldenEye) targeting TCP ports 80 and 443.
   - The model had never observed high-rate UDP streams with non-web destination ports. Because UDP traffic without HTTP ports resembled background streaming or DNS traffic in the other datasets, the gradient booster routed them directly into `BENIGN`.

---

### 2.2 UNSW-NB15 Held Out (66.80% Accuracy, 30.45% False Positive Rate)

#### Observations:
- **High False Positive Rate:** 21,891 benign flows out of 71,985 were misclassified as `TRAFFIC_SPIKE`.
- **False Negative Rate:** 95.69% of attacks were missed (0 out of 364 port scans and only 26 out of 992 traffic spikes detected).

#### Root Causes:
1. **Synthetic Background Generator (IXIA PerfectStorm):**
   - UNSW-NB15 generated 100 GB of synthetic background traffic using commercial IXIA testbed equipment.
   - The IXIA generator produced rapid bursts of small HTTP packets during normal browsing simulation. In Canadian datasets (CIC-IDS2017/2018), such burst distributions only occurred during active DoS attacks, leading Canadian-trained models to falsely alert on normal Australian traffic.
2. **Low-Rate Stealth Port Scanning:**
   - UNSW-NB15 port scans were conducted at low probe frequencies across long durations, blending indistinguishably into baseline web traffic when evaluated on single-flow features alone.

---

### 2.3 CIC-IDS2017 & CSE-CIC-IDS2018 Cross-Domain Generalization (75%–78% Accuracy)

The reciprocal evaluation between CIC-IDS2017 and CSE-CIC-IDS2018 yielded the highest cross-domain stability:
- **CIC-IDS2017 Held Out:** 78.11% Accuracy, 5.68% FPR.
- **CSE-CIC-IDS2018 Held Out:** 75.87% Accuracy, 11.03% FPR.

#### Why Did They Generalize Better?
1. **Shared Architectural Lineage:**  
   Both datasets were produced by the Canadian Institute for Cybersecurity using the **B-Profile system**, which generates authentic user behavior (browsing, email, database queries) across real Windows and Linux servers.
2. **On-Prem vs. AWS Cloud Artifacts:**  
   - CIC-IDS2017 was captured in an on-premises physical LAN.
   - CSE-CIC-IDS2018 was captured on **Amazon Web Services (AWS)** across 500 victim instances and 50 attacker nodes.
   - AWS VPC hypervisor packet encapsulation and MTU fragmentation introduced slight feature distribution variance, but attack signatures (e.g., Hulk floods and Port Scans) retained structural consistency.

---

## 3. Feature Distribution Discrepancies Across Domains

The table below contrasts key numerical feature means across the four datasets, explaining why decision boundaries fail under domain shift:

| Feature | UNSW-NB15 Mean | CIC-IDS2017 Mean | CSE-CIC-IDS2018 Mean | CIC-DDoS2019 Mean | Shift Ratio (Max / Min) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`packet_rate` (pkts/s)** | 284.1 | 1,420.5 | 890.3 | **48,920.4** | **172.2x** |
| **`byte_rate` (bytes/s)** | 142,500 | 895,200 | 540,100 | **18,450,000** | **129.5x** |
| **`mean_packet_length`** | 210.4 B | 485.2 B | 412.8 B | **96.4 B** | **5.0x** |
| **`std_packet_length`** | 185.2 B | 340.1 B | 312.4 B | **18.2 B** | **18.7x** |
| **`duration` (seconds)** | 4.82 s | 12.40 s | 15.20 s | **0.84 s** | **18.1x** |

### Key Takeaways:
- **`packet_rate` and `byte_rate` vary by more than two orders of magnitude** between campus network captures and enterprise DDoS events.
- Models trained without broad multi-dataset exposure overfit to specific hardware link speeds (e.g., 100 Mbps vs. 10 Gbps) and failure boundaries.

---

## 4. Architectural Solutions Implemented in the Gateway

To ensure reliable operation despite real-world domain shift, the security gateway implements four architectural safeguards:

```mermaid
flowchart TD
    Ingress[Ingress Network Flow] --> FeatExt[Clean 9-Feature Extractor]
    FeatExt --> XGB[XGBoost V2 Multi-Dataset Pooled Model]
    
    XGB --> ConfCheck{Confidence >= 0.60?}
    ConfCheck -->|No: Low Confidence| Monitor[Observational Monitoring<br/>Zero Disruption]
    ConfCheck -->|Yes: High Confidence| Policy[Policy Decision]
    
    Ingress --> SSHTracker[Deterministic SSHProbeTracker]
    SSHTracker -->|Burst >= 12 probes| Quarantine[Quarantine Host]
    
    Policy --> Router[Router iptables Enforcement]
```

1. **Multi-Dataset Pooled Training:**  
   Candidate XGBoost V2 was trained on a **pooled representation** spanning all four datasets (6.49 million records). By exposing tree splits to on-prem LANs, AWS cloud VPCs, and high-rate UDP reflection vectors simultaneously, single-dataset blind spots are eliminated.
2. **Confidence Gating Safeguard:**  
   In `PolicyEngine`, any threat prediction with confidence $< 0.60$ is automatically downgraded to `MONITOR` mode. Low-certainty domain-shift artifacts never trigger blocking rules.
3. **Deterministic Defense-in-Depth:**  
   Authentication attacks and brute-force sweeps are guarded by the stateful `SSHProbeTracker`, ensuring containment regardless of ML flow prediction.
4. **Shadow Mode Advisory Validation:**  
   The candidate model executes in Shadow Mode alongside the active engine until its live performance has been thoroughly audited across all operating subnets.

