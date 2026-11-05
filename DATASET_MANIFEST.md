# Authoritative Dataset Manifest: Big Data Intrusion Benchmark (10M Raw Ceiling)

**Generated:** 2026-11-05T19:09:23.329808+00:00  
**Total Raw Records Acquired & Inspected:** 11,397,869  
**Raw Acquisition Ceiling Target:** 10,000,000  
**Total Cleaned and Validated Records:** 6,593,274  
**Manifest Status:** ACTIVE & CRYPTOGRAPHICALLY VERIFIED

---

## 1. Multi-Source Raw Acquisition & Cleaning Summary

| Dataset Source | Raw Ingested | Cleaned & Staged | Duplicates / Corrupt Dropped | Final Retention Rate |
|---|---|---|---|---|
| **UNSW-NB15** | 2,059,415 | 1,365,612 | 693,803 | 66.31% |
| **CIC-IDS2017** | 2,830,743 | 1,783,439 | 1,047,304 | 63.00% |
| **CSE-CIC-IDS2018** | 3,145,724 | 1,689,814 | 1,455,910 | 53.72% |
| **CIC-DDoS2019** | 3,361,987 | 1,754,409 | 1,607,578 | 52.18% |
| **COMBINED FINAL** | **11,397,869** | **6,593,274** | **4,804,595** | **57.85%** |

---

## 2. Partition Splitting and Storage (Stratified 70/15/15)

Data partitions were generated via streaming chunked stratified sampling to ensure identical class distributions across all three splits:

| Split | Record Count | Percentage | Parquet Storage File | File Size | SHA-256 Checksum |
|---|---|---|---|---|---|
| **Train** | 4,615,283 | 70.0% | `data/processed/train.parquet` | 116.82 MB | `ca67b343b9cf45ce65d0052b03712d592aa4076f848412c485edebde6df7c2c7` |
| **Validation** | 988,985 | 15.0% | `data/processed/val.parquet` | 26.20 MB | `2bb47b76df6adce0e93e00243363714204914043a38ef3663d336f14375a1b27` |
| **Test** | 989,006 | 15.0% | `data/processed/test.parquet` | 26.20 MB | `5416ab8beb41b9f16e5e480ccbddc26546949e6540671e7f2f97f619e773bd2a` |
| **TOTAL** | **6,593,274** | **100.0%** | — | **169.22 MB** | Verified Multi-Partition |

---

## 3. Final Multi-Class Target Distribution

| Class Name | Train Split (70%) | Val Split (15%) | Test Split (15%) | Total Count | Overall Proportion |
|---|---|---|---|---|---|
| `BENIGN` | 2,950,520 | 632,254 | 632,255 | 4,215,029 | 63.93% |
| `TRAFFIC_SPIKE` | 1,438,671 | 308,287 | 308,287 | 2,055,245 | 31.17% |
| `PORT_SCAN` | 133,405 | 28,586 | 28,587 | 190,578 | 2.89% |
| `BRUTE_FORCE` | 70,429 | 15,092 | 15,092 | 100,613 | 1.53% |
| `SUSPICIOUS_TRANSFER` | 22,258 | 4,766 | 4,785 | 31,809 | 0.48% |
| **SUM** | **4,615,283** | **988,985** | **989,006** | **6,593,274** | **100.00%** |

---

## 4. Gateway Feature Schema Compliance & Types

All records strictly conform to the 10-feature Layer 3/Layer 4 vector in exact order:

| Index | Feature Name | Storage Type | Minimum Value | Maximum Value | Description / Unit |
|---|---|---|---|---|---|
| 0 | `packet_count` | `float64` | 1.0 | 3,115,000.0 | Total cumulative packets observed in bidirectional flow |
| 1 | `byte_count` | `float64` | 0.0 | 2,860,000,000.0 | Total cumulative payload bytes observed |
| 2 | `duration` | `float64` | 0.0 | 120.0 | Elapsed flow active lifetime in seconds |
| 3 | `conn_rate` | `float64` | 0.0 | 50,000.0 | Active connections / sessions per second |
| 4 | `dst_port` | `float64` | 0.0 | 65,535.0 | Destination transport service port (TCP/UDP) |
| 5 | `unique_dst_ports` | `float64` | 1.0 | 65,535.0 | Unique destination ports contacted in window |
| 6 | `failed_auth_count`| `float64` | 0.0 | 10,000.0 | Failed authentication attempts / error bursts |
| 7 | `bytes_per_sec` | `float64` | 0.0 | 1,000,000,000.0 | Average byte transmission bandwidth rate (B/s) |
| 8 | `packets_per_sec` | `float64` | 0.0 | 2,000,000.0 | Average packet transmission rate (pkt/s) |
| 9 | `avg_packet_size` | `float64` | 0.0 | 65,535.0 | Mean packet size in bytes ($\frac{\text{byte\_count}}{\text{packet\_count}}$) |

Metadata columns included in parquet splits for traceability:
- `label` (`string`): Production classification label (`BENIGN`, `PORT_SCAN`, `BRUTE_FORCE`, `TRAFFIC_SPIKE`, `SUSPICIOUS_TRANSFER`).
- `original_label` (`string`): Exact raw label from the benchmark dataset source.
- `dataset_source` (`string`): Originating benchmark dataset (`UNSW-NB15`, `CIC-IDS2017`, `CSE-CIC-IDS2018`, `CIC-DDoS2019`).
