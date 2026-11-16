# FINAL KNOWN LIMITATIONS & OPERATIONAL BOUNDARIES
## Adaptive AI-Powered Security Gateway for Hybrid Cloud

**Document Status:** FROZEN LIMITATIONS DISCLOSURE  
**Classification:** Academic Research Prototype  
**Release Baseline:** Phase 22.8.5 / Phase 22.9  
**Execution Timestamp:** 2026-11-17T01:34:00+05:30

---

## 1. Machine Learning & Threat Detection Boundaries

### 1.1 Cross-Dataset Domain Generalization
- **Training Foundation:** The Big Data XGBoost V2 model was trained on 6.49 million flow records aggregated from three benchmark academic corpora: CIC-IDS2017, UNSW-NB15, and CSE-CIC-IDS2018.
- **Limitation:** In real-world enterprise deployments, network background noise, emerging application protocols (e.g., HTTP/3 QUIC, TLS 1.3 encrypted SNI), and non-standard packet fragmentations may induce distribution shift.
- **Operational Impact:** While the model achieves >98% accuracy on representative benchmark evaluation splits, novel zero-day attack vectors not present in the training corpora may be classified as `BENIGN` or produce lower confidence scores.
- **Mitigation:** The system retains the 100-tree Random Forest model as a zero-downtime standby rollback (`production_rf`) and supports periodic offline retraining via the model registry.

### 1.2 Fixed 9-Feature Flow Abstraction
- **Limitation:** Deep packet inspection (DPI) of payload contents is deliberately omitted in favor of flow metadata (timing, packet counts, bytes, and destination ports).
- **Operational Impact:** Sophisticated application-layer injection attacks (e.g., SQL injection, command injection) that mimic benign HTTP traffic lengths and timings cannot be reliably classified by network flow features alone without complementary WAF or host-level telemetry.

---

## 2. Multi-Cloud & Telemetry Ingestion Boundaries

### 2.1 AWS Read-Only Integration Status
- **Implementation:** The AWS adapter (`backend/app/cloud/adapters/aws`) strictly executes read-only operations using AWS STS AssumeRole and `Describe*` / `Get*` APIs.
- **Limitation:** The gateway does NOT alter AWS Security Group rules, Network ACLs, or Route 53 entries dynamically.
- **VPC Flow Logs Lag:** AWS VPC Flow Logs delivered via Amazon S3 or CloudWatch Logs exhibit standard AWS ingestion delays of 5 to 15 minutes. Real-time sub-second threat containment cannot be achieved solely through CloudWatch/S3 log ingestion.

### 2.2 Azure & GCP Provider Stubs
- **Implementation:** Azure and GCP integrations are implemented as normalized architectural abstraction layers (`backend/app/cloud/adapters/azure` and `gcp`).
- **Limitation:** Unlike the AWS adapter which supports live AWS credential verification, the Azure and GCP adapters operate as extensible structural stubs without live API connectivity or automated cloud discovery.

---

## 3. Policy Containment & Enforcement Boundaries

### 3.1 Strict DRY_RUN Policy Enforcement
- **Limitation:** Live kernel firewall packet dropping is deliberately disabled.
- **Operational Impact:** When a threat is detected and a containment rule is generated, the rule is logged, tracked, and simulated in the database and UI, but is NOT installed into the host OS or Linux kernel forwarding tables.
- **Rationale:** Strict safety requirement to prevent unintended isolation of user workloads, administrative lockouts, or operational disruption in shared development environments.

### 3.2 Linux Bridge / Iptables Concurrency
- **Limitation:** The hybrid lab router emulates network perimeter filtering using standard Linux `iptables`. In high-throughput multi-gigabit scenarios, iptables linear rule evaluation introduces latency compared to eBPF/XDP hardware-offloaded datapaths.

---

## 4. Architectural & Deployment Boundaries

### 4.1 Standalone Windows Executable vs. Docker Lab
- **Limitation:** The standalone Windows binary (`AdaptiveSecurityGateway.exe`) runs on the host Windows filesystem. It does NOT share the Docker named volume (`hybrid_lab_telemetry`).
- **Operational Impact:** Manual scenario triggers executed from the standalone EXE on port 8000 cannot communicate with the Docker `traffic-generator` container. Scenario execution must be performed through the Docker dashboard on `http://localhost:5175`.

### 4.2 Python Runtime & Packet Capture Throughput
- **Limitation:** The Scapy packet parser and flow aggregator are single-threaded Python processes constrained by the Python Global Interpreter Lock (GIL).
- **Operational Impact:** The sensor is optimized for laboratory emulation and moderate traffic rates (<10,000 packets/sec). Production enterprise line-rate 10Gbps+ packet capture would require a native C/Rust capture engine (e.g., DPDK or PF_RING).

---

## 5. Scope Statement

The Adaptive AI-Powered Security Gateway for Hybrid Cloud is an **advanced academic research prototype** designed to demonstrate the feasibility of zero-downtime ML model governance, explainable AI attribution, and automated hybrid cloud policy generation. It is not warranted for mission-critical production perimeter defense without dedicated production hardening and infrastructure integration.
