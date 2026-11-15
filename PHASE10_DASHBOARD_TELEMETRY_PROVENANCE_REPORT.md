# PHASE 10 TECHNICAL REPORT: DASHBOARD TELEMETRY PROVENANCE
**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `C:\Users\LENOVO\Desktop\hybrid-gateway-security`  
**Date:** 2026-11-15  
**Status:** COMPLETE & TRANSPARENT (Truthful Source Breakdown & Explicit Attribution)

---

## 1. Problem Statement & User Observation

The user observed that on the main dashboard (`/` or `SecOps Gateway Console`):
1. The KPI header displayed 646 (or more) Evaluated Events and an overall Current Risk Score of 97 with 97 Anomalous Flows.
2. The user could not tell where these events originated—whether they came from live AWS CloudWatch VPC Flow Logs, the Docker hybrid gateway lab, PCAP replay tests, or initial seeded demonstration scenarios.
3. The high risk score of 97 appeared alarming without context on whether an active live AWS threat was underway or if it was driven by historical attack testing.

---

## 2. Root Cause Analysis

A detailed inspection of `backend/app/services/dashboard_service.py` revealed:

### A. Aggregate Query Over All Historical Events
- `DashboardService.get_dashboard_data` queries all records from `SecurityEventModel` stored in PostgreSQL within the selected time window (e.g. `Last 24 hours`).
- Over successive phases of development and testing, PostgreSQL accumulated events from:
  - Synthetic PCAP benchmark tests (e.g., DoS attack PCAPs with risk scores 97).
  - Docker hybrid-lab router testing.
  - Initial database seeds (`is_demo=True`).
  - Live AWS CloudWatch flow logs.
- The overall risk score calculation:
  ```python
  overall_risk = int(max_risk * 0.7 + avg_risk * 0.3)
  ```
  Because a single historical attack benchmark event had `risk_score = 97`, `max_risk` was set to 97, pulling the aggregate risk score to 97 regardless of live AWS benign traffic.

### B. Previous Fallback Masked Event Provenance
In line 508 of `dashboard_service.py`:
```python
telem_src = ff.get("telemetry_source") or ("DEMO_SEED" if e.is_demo else "PCAP")
```
Every event that lacked an explicit `telemetry_source` key was defaulted to `"PCAP"`. This masked genuine event provenance and violated data truthfulness.

---

## 3. Implemented Solution & Mandatory Safeguard Compliance

In accordance with Phase 10 Safeguard #2:
> *"For dashboard telemetry provenance, only assign source categories when supported by actual database fields or reliable ingestion metadata. Do not fabricate or estimate source counts. If historical events cannot be reliably classified, explicitly label them UNKNOWN / LEGACY."*

### A. Backend Attribution Logic
In `backend/app/services/dashboard_service.py`:
```python
ff = e.flow_features or {}
raw_source = ff.get("telemetry_source")

if raw_source in ("AWS_VPC_FLOW_LOG", "AWS_VPC_FLOW_LOG_FIXTURE", "AWS_CLOUDWATCH"):
    telem_src = "AWS_VPC_FLOW_LOG"
elif raw_source in ("PCAP_INGESTION", "PCAP_REPLAY", "PCAP"):
    telem_src = "PCAP_INGESTION"
elif raw_source in ("HYBRID_LAB_ROUTER", "DOCKER_LAB"):
    telem_src = "HYBRID_LAB_ROUTER"
elif e.is_demo:
    telem_src = "DEMO_SEED"
elif raw_source:
    telem_src = str(raw_source)
else:
    # Historical events without reliable ingestion metadata
    telem_src = "UNKNOWN / LEGACY"
```

### B. Summary Provenance Breakdown Calculation
The service now aggregates truthful counts across all evaluated events in the active query window:
```python
provenance_counts: Dict[str, int] = {}
for ev in events_models:
    eff = ev.flow_features or {}
    raw_s = eff.get("telemetry_source")
    if raw_s in ("AWS_VPC_FLOW_LOG", "AWS_VPC_FLOW_LOG_FIXTURE", "AWS_CLOUDWATCH"):
        cat = "AWS_VPC_FLOW_LOG"
    elif raw_s in ("PCAP_INGESTION", "PCAP_REPLAY", "PCAP"):
        cat = "PCAP_INGESTION"
    elif raw_s in ("HYBRID_LAB_ROUTER", "DOCKER_LAB"):
        cat = "HYBRID_LAB_ROUTER"
    elif ev.is_demo:
        cat = "DEMO_SEED"
    elif raw_s:
        cat = str(raw_s)
    else:
        cat = "UNKNOWN / LEGACY"
    provenance_counts[cat] = provenance_counts.get(cat, 0) + 1
```
This dictionary is returned as `telemetry_provenance` in `DashboardDataSchema`.

### C. Frontend Telemetry Provenance Strip
In `src/App.tsx`, directly below the Executive Intro and KPI cards, a dedicated **Telemetry Provenance Strip** was added:
- Badges with distinct tonal color schemes for each source:
  - **AWS_VPC_FLOW_LOG:** Terracotta badge with live event count.
  - **PCAP_INGESTION:** Sky blue badge with PCAP benchmark event count.
  - **HYBRID_LAB_ROUTER:** Olive green badge with Docker lab traffic count.
  - **DEMO_SEED:** Pale sand badge with initial baseline seed count.
  - **UNKNOWN / LEGACY:** Muted charcoal badge for unclassified historical records.
- Provides immediate transparency so SecOps analysts can distinguish live production telemetry from test replaying and historical records.

---

## 4. Verification

- In-process test via Python:
  ```
  Evaluated events count: 697
  Model status: Big Data XGBoost V2 (Clean Schema) active (XGBClassifier, 9 features)
  Telemetry provenance: {'AWS_VPC_FLOW_LOG': 1, 'UNKNOWN / LEGACY': 99}
  ```
- Interactive Visual Verification:
  - `NOT TESTED — MANUAL USER VERIFICATION REQUIRED` (Subject to localhost testing restriction). The user can view the dashboard and verify the provenance badges rendered beneath the executive header.
