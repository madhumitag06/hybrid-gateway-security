# Big Data ML Training: Dataset Cleaning & Preprocessing Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Total Raw Records Ingested:** 11,397,869  
**Cleaned & Validated Records Retained:** 6,593,274 (57.85% retention)  
**Total Records Purged:** 4,804,595 (42.15% dropped)  
**Execution Date:** 2026-11-05 / 2026-11-06  
**Status:** COMPLETE & VERIFIED

---

## 1. Cleaning Strategy & Sanitization Philosophy

Network intrusion datasets often suffer from sensor artifacts, network loopback duplicates, TCP retransmission echoes, null values, division-by-zero artifacts (e.g., `Infinity` flow rates), and header misalignments.

To ensure strict production compatibility with the live gateway's `LiveFlowAggregator` and `FeatureExtractor` pipelines, we enforced four rigorous cleansing criteria:

1. **Non-Finite & Missing Value Removal:**
   - Any flow record containing `NaN`, `null`, `+inf`, `-inf`, or unparseable ASCII strings in numeric fields was purged.
2. **Physical Feasibility Constraints:**
   - Flow packet count must be strictly positive: $\text{packet\_count} \ge 1$.
   - Flow byte count must be strictly non-negative: $\text{byte\_count} \ge 0$.
   - Flow duration must be non-negative: $\text{duration} \ge 0.0$.
   - Destination port must fall within valid RFC 793/768 boundaries: $0 \le \text{dst\_port} \le 65535$.
3. **Exact Flow Deduplication:**
   - High-rate packet captures frequently log identical flow keys multiple times due to multiple tap points and retransmissions. All identical 10-feature flow vectors with duplicate class labels were deduplicated to prevent data leakage and artificial inflation of validation scores.
4. **Header and Corrupt Row Exclusion:**
   - Periodic CSV header strings embedded mid-file (frequent in multi-part CICFlowMeter captures) were stripped.

---

## 2. Quantitative Cleansing Breakdown by Dataset

| Dataset | Raw Records Available | Dropped Invalid / Non-Finite / Non-Positive | Dropped Exact Duplicates | Total Dropped | Cleaned Records Retained | Retention Rate |
|---|---|---|---|---|---|---|
| **UNSW-NB15** | 2,059,415 | 0 | 693,803 | 693,803 | 1,365,612 | 66.31% |
| **CIC-IDS2017** | 2,830,743 | 0 | 1,047,304 | 1,047,304 | 1,783,439 | 63.00% |
| **CSE-CIC-IDS2018** | 3,145,724 | 30,609 | 1,425,301 | 1,455,910 | 1,689,814 | 53.72% |
| **CIC-DDoS2019** | 3,361,987 | 550 | 1,607,028 | 1,607,578 | 1,754,409 | 52.18% |
| **TOTALS** | **11,397,869** | **31,159** | **4,773,436** | **4,804,595** | **6,593,274** | **57.85%** |

---

## 3. Class Distribution: Before vs. After Cleaning & Mapping

The diverse raw labels across all four datasets (comprising over 30 unique attack sub-categories) were mapped deterministically into the gateway's five production classes:
- `BENIGN`
- `PORT_SCAN`
- `BRUTE_FORCE`
- `TRAFFIC_SPIKE`
- `SUSPICIOUS_TRANSFER`

### 3.1 UNSW-NB15
- **Cleaned Total:** 1,365,612 records
- `BENIGN`: 1,310,728 (95.98%) — Normal background web, DNS, and operational flows.
- `SUSPICIOUS_TRANSFER`: 30,182 (2.21%) — Mapped from Exploits, Generic, Backdoor, Shellcode, Worms.
- `TRAFFIC_SPIKE`: 18,069 (1.32%) — Mapped from DoS and Fuzzers.
- `PORT_SCAN`: 6,633 (0.49%) — Mapped from Reconnaissance.

### 3.2 CIC-IDS2017
- **Cleaned Total:** 1,783,439 records
- `BENIGN`: 1,460,633 (81.90%) — Authentic daily operational profile traffic.
- `TRAFFIC_SPIKE`: 311,537 (17.47%) — DoS Hulk, GoldenEye, Slowloris, Slowhttptest, DDoS.
- `BRUTE_FORCE`: 7,051 (0.40%) — SSH-Patator and FTP-Patator password exhaustion.
- `PORT_SCAN`: 2,591 (0.15%) — PortScan tool sweeps.
- `SUSPICIOUS_TRANSFER`: 1,627 (0.09%) — Botnet C2 traffic and infiltration attempts.

### 3.3 CSE-CIC-IDS2018
- **Cleaned Total:** 1,689,814 records
- `BENIGN`: 1,424,700 (84.31%) — Cloud-scale baseline enterprise network traffic.
- `TRAFFIC_SPIKE`: 171,552 (10.15%) — DoS LOIC, HOIC, and Slowloris attacks.
- `BRUTE_FORCE`: 93,562 (5.54%) — Distributed SSH and FTP brute-force credential stuffing.

### 3.4 CIC-DDoS2019
- **Cleaned Total:** 1,754,409 records
- `TRAFFIC_SPIKE`: 1,554,087 (88.58%) — NTP, Syn, and UDP-lag reflection floods.
- `PORT_SCAN`: 181,354 (10.34%) — Portmap service sweeps.
- `BENIGN`: 18,968 (1.08%) — Background legitimate client inquiries.

### 3.5 Consolidated 5-Class Target Distribution
Across the final consolidated 6,593,274 cleaned records:
- **`BENIGN`:** 4,215,029 (63.93%)
- **`TRAFFIC_SPIKE`:** 2,055,245 (31.17%)
- **`PORT_SCAN`:** 190,578 (2.89%)
- **`BRUTE_FORCE`:** 100,613 (1.53%)
- **`SUSPICIOUS_TRANSFER`:** 31,809 (0.48%)

---

## 4. Chunked & Memory-Safe Processing Validation

- **Pipeline Execution:** `ml/data/clean_and_preprocess.py`
- **Memory Safety:** Processed CSVs in streaming chunks of 250,000 rows. Peak memory usage remained under 1.8 GB RAM on a 32 GB machine, completely preventing `ArrayMemoryError` or paging thrashing.
- **Output Storage:** Each cleaned source was staged in `data/staging/` as Snappy-compressed Apache Parquet before final dataset merging, reducing intermediate disk consumption to 434 MB.

