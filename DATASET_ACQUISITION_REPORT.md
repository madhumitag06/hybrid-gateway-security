# Big Data ML Training: Dataset Acquisition Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Target Raw Ingestion Target:** Up to 10,000,000 Raw Records  
**Total Raw Records Acquired & Inspected:** 11,397,869  
**Execution Date:** 2026-11-05 / 2026-11-06  
**Status:** COMPLETE & VERIFIED

---

## 1. Executive Summary

To achieve production-grade intrusion detection and robust domain generalization across heterogeneous network boundaries (on-premises datacenter and AWS VPC cloud environments), we independently acquired and verified four premier public benchmark intrusion detection datasets:
1. **UNSW-NB15** (Australian Defence Force Academy / University of New South Wales)
2. **CIC-IDS2017** (Canadian Institute for Cybersecurity, UNB)
3. **CSE-CIC-IDS2018** (Communications Security Establishment & UNB, hosted on AWS)
4. **CIC-DDoS2019** (Canadian Institute for Cybersecurity, UNB)

The raw record acquisition target of 10,000,000 records was exceeded, reaching **11,397,869 raw flow records** (~2.86 GB compressed/archive downloads, expanding to >4.5 GB uncompressed). Every archive and dataset was SHA-256 verified against cryptographic checksums and cataloged in `data/manifests/download_manifest.json`.

---

## 2. Ingestion Matrix & Cryptographic Provenance

| Dataset | Filename | Storage Format | Archive Size | Uncompressed Records | SHA-256 Cryptographic Hash | Source / Origin URL |
|---|---|---|---|---|---|---|
| **UNSW-NB15** | `UNSW_Flow.parquet` | Apache Parquet (Snappy) | 174.88 MB | 2,059,415 | `8129db1cef95763a45072052af30a4c954af18b48abb6176f3d8ab732eb7d274` | Hugging Face Hub (`rdpahalavan/UNSW-NB15`) |
| **CIC-IDS2017** | `MachineLearningCSV.zip` | Multi-CSV ZIP Archive | 224.21 MB | 2,830,743 | `c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928` | Hugging Face Hub (`bencorn/CICIDS2017`) / UNB Mirror |
| **CSE-CIC-IDS2018** | `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | Plaintext CSV | 358.53 MB | 1,048,575 | `fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b` | Official AWS S3 Public Bucket (`cse-cic-ids2018`) |
| **CSE-CIC-IDS2018** | `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | Plaintext CSV | 341.63 MB | 1,048,575 | `acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147` | Official AWS S3 Public Bucket (`cse-cic-ids2018`) |
| **CSE-CIC-IDS2018** | `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | Plaintext CSV | 318.26 MB | 1,048,574 | `1a4919faa0c49c7af97230b0c2d076eba23ee6dd81103a3801d51ac316355d8b` | Official AWS S3 Public Bucket (`cse-cic-ids2018`) |
| **CIC-DDoS2019** | `03-11_Portmap.csv` | Plaintext CSV | 74.97 MB | 191,694 | `d0148da21f3c645b32b21b59386721eddd497a16e3de4e2950391e575fca2e28` | Hugging Face Hub (`baalajimaestro/CICDDoS2019`) |
| **CIC-DDoS2019** | `01-12_UDPLag.csv` | Plaintext CSV | 150.65 MB | 370,605 | `f67708a8462509932759ffed7eb92dca0f423267609d1be38a461708d4ea5b7e` | Hugging Face Hub (`baalajimaestro/CICDDoS2019`) |
| **CIC-DDoS2019** | `01-12_DrDoS_NTP.csv` | Plaintext CSV | 615.13 MB | 1,217,007 | `b4ae33b2a22975f2c4c8b0e2bfc501fee38dae274dca37d4b01010de059c9c2c` | Hugging Face Hub (`baalajimaestro/CICDDoS2019`) |
| **CIC-DDoS2019** | `01-12_Syn.csv` | Plaintext CSV | 607.79 MB | 1,582,681 | `05a272a7005be14262d3929ad16877db42fc74a03032a3a5b58d0230ab08896a` | Hugging Face Hub (`baalajimaestro/CICDDoS2019`) |
| **TOTALS** | **9 Source Files** | — | **2.86 GB** | **11,397,869** | Verified Multi-Hash | — |

---

## 3. Dataset Characteristics and Traffic Context

### 3.1 UNSW-NB15 (2,059,415 records)
- **Origin:** Cyber Range Lab of UNSW Canberra, synthetic attack injections mixed with real normal background traffic.
- **Traffic Nature:** High-volume benign traffic with modern network attacks: Exploits, Fuzzers, Reconnaissance (port scans), Backdoors, DoS, Analysis, Generic, and Worms.
- **Key Relevance to Gateway:** Supplies realistic advanced exploitation attacks and subtle multi-stage infiltrations mapped to `SUSPICIOUS_TRANSFER`.

### 3.2 CIC-IDS2017 (2,830,743 records)
- **Origin:** University of New Brunswick (UNB) B-Profile system, simulating authentic user interactions over HTTP, HTTPS, FTP, SSH, and email across 5 days.
- **Traffic Nature:** Includes FTP-Patator and SSH-Patator brute force, DoS (Slowloris, Slowhttptest, Hulk, GoldenEye), Heartbleed, PortScan, Botnets, Infiltration, and Web Attacks.
- **Key Relevance to Gateway:** Directly reflects the gateway's target classes: `PORT_SCAN`, `BRUTE_FORCE`, `TRAFFIC_SPIKE`, and `BENIGN`.

### 3.3 CSE-CIC-IDS2018 (3,145,724 records)
- **Origin:** Communications Security Establishment (CSE) & UNB, executed on AWS infrastructure consisting of 421 victim machines, 50 attacking nodes, and 30 servers.
- **Traffic Nature:** Massive-scale cloud network captures featuring DoS attacks, DDoS LOIC/HOIC, Botnets, and Infiltration, alongside high-bandwidth cloud benign communications.
- **Key Relevance to Gateway:** Mirrors AWS VPC traffic dynamics, VPC Flow Logs, and cloud topology routing behaviors essential for the gateway's hybrid-cloud perimeter.

### 3.4 CIC-DDoS2019 (3,361,987 records)
- **Origin:** UNB Canadian Institute for Cybersecurity, high-volume DDoS benchmark recording 12 distinct reflection and exploitation DDoS attack vectors.
- **Traffic Nature:** DrDoS_NTP, DrDoS_DNS, Syn floods, UDP-Lag, Portmap, and NetBIOS amplification attacks.
- **Key Relevance to Gateway:** Provides stress-grade volume benchmarks for `TRAFFIC_SPIKE` and high-rate scanning, testing gateway throughput and resilience against volumetric exhaustion.

---

## 4. Download Execution Details & System Storage Footprint

- **Automated Ingestion Script:** `ml/data/download_datasets.py`
- **Streaming Strategy:** Chunked HTTP streaming with 64 KB buffers, preventing large RAM allocation spikes during download.
- **Storage Management:**
  - Raw archive storage: `C:\Users\LENOVO\Desktop\hybrid-gateway-security\data\raw\` (2.86 GB)
  - Extracted intermediate storage: `C:\Users\LENOVO\Desktop\hybrid-gateway-security\data\extracted\` (~850 MB)
  - Available host storage throughout execution: Maintained >8.5 GB free on Drive C: and >85.0 GB on Drive D:.
- **Verification:** Every downloaded file passed bit-level SHA-256 checksum matching prior to decompression.

