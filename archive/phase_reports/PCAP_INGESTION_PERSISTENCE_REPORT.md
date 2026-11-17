# PCAP INGESTION PERSISTENCE & FLOW RECOVERY REPORT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Component:** Telemetry & PCAP Ingestion Engine  
**Status:** COMPLETED & VERIFIED  

---

## 1. Executive Summary

Previously, PCAP ingestion results (evaluated packets, aggregated flow records, continuous risk scores, attack classifications, and policy decisions) resided exclusively in client-side React component state. When operators navigated between UI tabs, refreshed the browser, or restarted `AdaptiveSecurityGateway.exe`, all parsed flow telemetry was wiped, forcing operators to repeatedly re-upload captures.

In addition, Scapy generated a startup warning on Windows:
`WARNING: No libpcap provider available ! pcap won't be used`
This warning was investigated and confirmed to be completely benign for offline PCAP/PCAPNG file parsing.

This workstream established a permanent PostgreSQL persistence layer for PCAP ingestion, added REST API endpoints for state recovery, and updated the frontend to automatically restore the most recent capture upon navigation.

---

## 2. Technical Investigation: Scapy Libpcap Warning

1. **Origin of Warning**:
   - Scapy's warning `WARNING: No libpcap provider available ! pcap won't be used` is emitted by `scapy.arch.windows` when neither Npcap nor WinPcap is installed on the host operating system.
   - This warning applies strictly to **live hardware network interface sniffing** (promiscuous mode promiscuous socket binding).

2. **Offline File Parsing Mechanism**:
   - The security gateway processes pre-captured files via `scapy.utils.PcapReader`.
   - `PcapReader` reads offline files purely using Python's built-in `struct.unpack` and binary file I/O.
   - It has **zero dependency on libpcap, Npcap, or WinPcap**.
   - Offline parsing was verified across 4 benchmark PCAPs (`benign_web.pcap`, `port_scan.pcap`, `traffic_spike.pcap`, `suspicious_transfer.pcap`) and uploaded user PCAPs, extracting 100% of packets and flows with zero errors.

---

## 3. Database Architecture: `pcap_ingestions`

Created table `pcap_ingestions` in PostgreSQL:

| Column | Type | Description |
|---|---|---|
| `id` | VARCHAR | Unique ingestion identifier (e.g. `pcap-9f8a...`) |
| `filename` | VARCHAR | Original capture file name |
| `file_size_bytes` | INTEGER | File size in bytes |
| `status` | VARCHAR | Status (`PROCESSING`, `COMPLETED`, `FAILED`) |
| `packets_processed` | INTEGER | Total packets decoded from PCAP |
| `flows_generated` | INTEGER | Bidirectional IP flows constructed |
| `flows_evaluated` | INTEGER | Evaluated flows with ML classifications |
| `high_risk_flows_count` | INTEGER | Count of flows exceeding risk score threshold |
| `duration_ms` | INTEGER | Total processing and inference latency in ms |
| `attack_distribution` | JSON | Counts of detected threat classes |
| `metrics` | JSON | Throughput, packet breakdown, and timings |
| `summary_results` | JSON | Evaluated flow records with predictions and features |
| `created_at` | TIMESTAMP WITH TIME ZONE | Ingestion completion timestamp |

---

## 4. REST API Endpoints

Three persistent endpoints were implemented in `backend/app/api/v1/ingest.py`:

1. `GET /api/v1/ingest/latest`:
   - Returns the most recent completed or active ingestion record from PostgreSQL.
   - If no prior capture exists, returns `{"status": "NO_PREVIOUS_INGESTION", "ingestion": None}`.

2. `GET /api/v1/ingest/history`:
   - Supports paginated historical retrieval (`page`, `page_size`).
   - Returns total capture count, timestamps, flow counts, and file sizes.

3. `GET /api/v1/ingest/history/{ingestion_id}`:
   - Returns complete detailed flow summary, risk scores, and telemetry metrics for any past ingestion.

---

## 5. Frontend Persistence & Recovery Integration

Updated `src/components/PcapIngestView.tsx`:
- **Mount Lifecycle (`useEffect`)**: Automatically queries `getLatestIngestion()` on load. If an ingestion exists, the telemetry header, summary cards, and evaluated flows table are populated immediately.
- **Historical Ledger**: Added a dedicated `Ingestion History` toggle and table displaying all past PCAP runs. Analysts can click `Load` on any historical capture to inspect its telemetry and flow vectors.
- **Dynamic Model Indicator**: Replaced static "Random Forest" copy with active model registry badges (`XGBoost V2 (Authoritative)` and `Random Forest (Standby Rollback)`).

---

## 6. Verification and Regression Testing

- Ingested test PCAP fixtures into PostgreSQL via automated pytest test `test_pcap_ingestion_persistence`.
- Verified `GET /api/v1/ingest/latest` returns `status: FOUND` and matching packet/flow counts.
- Verified `GET /api/v1/ingest/history` lists all past captures with pagination.
- Verified `GET /api/v1/ingest/history/{id}` retrieves complete flow arrays.
- Tested across UI builds (`npm run build`), confirming 0 TypeScript and bundling errors.

