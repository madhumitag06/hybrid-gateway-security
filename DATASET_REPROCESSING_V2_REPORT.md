# Big Data Dataset Reprocessing and Staging V2 Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** Phase 2 — Production-Grade Feature Engineering and Big Data XGBoost V2  
**Date:** November 2026  
**Status:** Complete & Verified

---

## Executive Summary

Following the Big Data ML Phase 1 audit (`BIGDATA_MODEL_FINAL_VALIDATION.md`), all four public benchmark intrusion datasets were completely reprocessed. The reprocessing pipeline was reconstructed from scratch (`ml/data/clean_and_preprocess_v2.py`) to eliminate synthetic telemetry injection (`failed_auth_count`), apply unified feature formulas (`calculate_conn_rate`), and partition the resulting dataset into stratified splits (`data/processed_v2/`).

A total of **6,499,075 clean, verified flow records** were generated across four benchmark network datasets, completely free of unobservable or synthetic attributes.

---

## 1. Reprocessing Methodology & Integrity Controls

### 1. Zero Synthetic Injection
In Phase 1, `failed_auth_count` was artificially assigned random integers ($[5, 25]$) for brute-force samples and $0$ for benign samples. In Phase 2:
- Synthetic injection was completely eliminated.
- The V2 schema extracts strictly 9 observable L3/L4 network features.
- All brute-force samples preserve their authentic empirical packet and byte distributions.

### 2. Rigorous Data Cleansing
Every raw flow record across all source files was validated against strict hygiene rules:
- **Infinity and NaN Handling:** Infinite values produced by zero duration or invalid division were dropped or clamped to physical maximums.
- **Negative Value Clamping:** Corrupt negative byte or packet counts (caused by signed 32-bit integer overflow in legacy capture software) were purged.
- **Port Number Sanitization:** Destination ports strictly validated in the range $[0, 65535]$.
- **Deduplication:** Repeated identical flows within sub-second intervals were filtered out.

---

## 2. Dataset Accounting by Source

| Benchmark Dataset | Staged File Path | Cleaned Records | File Size (MB) | Retention Rate | Primary Attack Coverage |
|:---|:---|:---:|:---:|:---:|:---|
| **UNSW-NB15** | `data/staging_v2/unsw_nb15.parquet` | 1,365,612 | 47.85 MB | 98.4% | Reconnaissance, Fuzzers, Exploits |
| **CIC-IDS2017** | `data/staging_v2/cic_ids2017.parquet` | 1,784,328 | 63.00 MB | 84.8% | SSH/FTP Brute Force, DoS/DDoS, PortScan |
| **CSE-CIC-IDS2018** | `data/staging_v2/cse_cic_ids2018.parquet` | 1,685,808 | 58.93 MB | 80.3% | Botnet, Infiltration, Brute Force |
| **CIC-DDoS2019** | `data/staging_v2/cic_ddos2019.parquet` | 1,663,327 | 30.25 MB | 83.2% | Amplification DDoS (NTP, DNS, LDAP, MSSQL) |
| **TOTAL (V2)** | `data/staging_v2/` | **6,499,075** | **200.03 MB** | **85.9%** | **Full 5-Class Hybrid Threat Landscape** |

---

## 3. Class Mapping & Overall Distribution

All disparate labels across the four source datasets were mapped into the 5 canonical gateway classes:

```
UNSW-NB15 / CIC-IDS2017 / CSE-CIC-IDS2018 / CIC-DDoS2019
 │
 ├── Benign / Normal ─────────────────────────────► BENIGN
 ├── PortScan / Reconnaissance ───────────────────► PORT_SCAN
 ├── SSH-Patator / FTP-Patator / Brute Force ─────► BRUTE_FORCE
 ├── DoS / DDoS / Infiltration / Spikes ──────────► TRAFFIC_SPIKE
 └── Bot / Backdoors / Exfiltration / Transfers ──► SUSPICIOUS_TRANSFER
```

### Cleaned V2 Dataset Totals:
- **`BENIGN`**: 4,215,991 records (64.87%)
- **`TRAFFIC_SPIKE`**: 2,055,251 records (31.62%)
- **`PORT_SCAN`**: 99,503 records (1.53%)
- **`BRUTE_FORCE`**: 96,521 records (1.49%)
- **`SUSPICIOUS_TRANSFER`**: 31,809 records (0.49%)
- **Total Records:** **6,499,075**

---

## 4. Final Partitioning and Cryptographic Checksums

The cleaned dataset was partitioned using stratified sampling (70% train, 15% validation, 15% test) via `ml/data/build_final_dataset_v2.py`. Streaming Parquet writers ensured memory consumption remained under 1.5 GB RAM throughout partitioning.

### Partition Inventory:

#### 1. Train Split (`train.parquet`)
- **Records:** 4,549,345 (70.0%)
- **File Size:** 152,774,618 bytes (145.70 MB)
- **SHA-256:** `4f537ff01cc26d0596bb6b66cb55c79c5255dd7f8f2c2466898b945e9aa8284d`
- **Class Breakdown:**
  - `BENIGN`: 2,951,191
  - `TRAFFIC_SPIKE`: 1,438,674
  - `PORT_SCAN`: 69,651
  - `BRUTE_FORCE`: 67,564
  - `SUSPICIOUS_TRANSFER`: 22,265

#### 2. Validation Split (`val.parquet`)
- **Records:** 974,855 (15.0%)
- **File Size:** 34,149,716 bytes (32.57 MB)
- **SHA-256:** `f70243da3a080f2e03e9aa75962707c3705bf51c9579320d21e95f959da4c541`
- **Class Breakdown:**
  - `BENIGN`: 632,398
  - `TRAFFIC_SPIKE`: 308,286
  - `PORT_SCAN`: 14,923
  - `BRUTE_FORCE`: 14,477
  - `SUSPICIOUS_TRANSFER`: 4,771

#### 3. Test Split (`test.parquet`)
- **Records:** 974,875 (15.0%)
- **File Size:** 34,139,345 bytes (32.56 MB)
- **SHA-256:** `57f1e8f3bd2068e32ae4a9db3808ef5951ecfa8711a34b107be01e312176a50c`
- **Class Breakdown:**
  - `BENIGN`: 632,402
  - `TRAFFIC_SPIKE`: 308,291
  - `PORT_SCAN`: 14,929
  - `BRUTE_FORCE`: 14,480
  - `SUSPICIOUS_TRANSFER`: 4,773

The complete manifest is recorded in `data/manifests/dataset_manifest_v2.json` and mirrored in `ml/models/candidates/bigdata_v2/dataset_manifest.json`.

