# Multi-Cloud Security, Networking & Containment Architecture

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Scope:** Amazon Web Services, Google Cloud Platform, Microsoft Azure, Docker Hybrid Lab  

---

## 1. Network Topology & Addressing Plan

The multi-cloud architecture establishes non-overlapping Class A and Class B CIDR blocks across all four participating network domains to facilitate clean routing, transit peering, and cross-cloud traffic classification:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              CROSS-CLOUD IP ADDRESSING PLAN                            │
├──────────────────────┬──────────────────────┬──────────────────────────────────────────┤
│ Network Domain       │ Assigned CIDR Block  │ Primary Purpose / Zone                   │
├──────────────────────┼──────────────────────┼──────────────────────────────────────────┤
│ On-Premises (Sim.)   │ 10.10.0.0/16         │ Legacy Data Center & Internal Endpoints  │
│ Docker Hybrid Lab    │ 10.10.10.0/24 (OnP)  │ Simulated client & database nodes        │
│                      │ 10.20.10.0/24 (Cld)  │ Simulated cloud workloads                │
│                      │ 10.30.10.0/24 (Mgmt) │ Lab Router Data Plane (10.30.10.2:8099)  │
│ AWS VPC Network      │ 10.20.0.0/16         │ Public ingress & private cloud subnets   │
│                      │ 10.20.10.0/24        │ Public DMZ & Security Gateway instances  │
│                      │ 10.20.20.0/24        │ Private application workload tier        │
│ GCP VPC Network      │ 10.40.0.0/16         │ Google Builders Hub cloud workloads      │
│                      │ 10.40.10.0/24        │ Subnetwork (us-central1)                 │
│ Azure VNet           │ 10.50.0.0/16         │ Microsoft Azure enterprise perimeter     │
│                      │ 10.50.10.0/24        │ Gateway subnet (eastus)                  │
│                      │ 10.50.20.0/24        │ Workload subnet                          │
└──────────────────────┴──────────────────────┴──────────────────────────────────────────┘
```

---

## 2. Traffic Classification & Directional Inference

The gateway classifies all inspected flows using `NetworkZoneClassifier` into directional categories:
- **`INTERNAL`**: Traffic originating and terminating within the same cloud subnet.
- **`CROSS_ZONE`**: Traffic traversing between on-prem and cloud, or between distinct cloud providers (e.g. AWS $\leftrightarrow$ GCP, Azure $\leftrightarrow$ AWS).
- **`INGRESS`**: Traffic from external or public untrusted IPs entering a protected subnet.
- **`EGRESS`**: Traffic initiated by internal workloads destined for external endpoints.

---

## 3. Cloud Containment Mechanisms

The gateway implements automated, reversible containment adapted to each cloud's native controls:

```
┌─────────────────┐     ┌────────────────────────────────────────────────────────────────┐
│  AI Detection   │────►│                   POLICY ENFORCEMENT ENGINE                    │
│ XGBoost V2 Risk │     │  Determines policy action: ALLOW, MONITOR, RESTRICT, or BLOCK  │
└─────────────────┘     └───────────────────────────────┬────────────────────────────────┘
                                                        │
                      ┌─────────────────────────────────┴────────────────────────────────┐
                      ▼                                 ▼                                ▼
            ┌───────────────────┐             ┌───────────────────┐            ┌───────────────────┐
            │   AWS Containment │             │  GCP Containment  │            │ Azure Containment │
            │  • Network ACL    │             │  • Cloud Firewall │            │  • Network Sec.   │
            │    Deny Entry     │             │    Priority 100   │            │    Group Inbound  │
            │  • SG Isolation   │             │    Deny Rule      │            │    Deny Rule      │
            └───────────────────┘             └───────────────────┘            └───────────────────┘
```

### 3.1 Containment Safeguards
1. **Management Allowlist:** Essential administrative ranges (`127.0.0.1/32`, `10.30.10.0/24`, `10.10.10.2/32`, etc.) are permanently protected from automated blocking.
2. **Default Dry-Run Mode:** All containment calls execute in simulation (`dry_run=True`) until explicitly unlocked by an authorized SecOps administrator via `POST /api/v1/enforcement/mode`.
3. **Automated Revert Command:** Every containment policy records an idempotent rollback command in PostgreSQL (`PolicyAuditLogModel`), enabling instantaneous remediation in the event of a false positive.

---

## 4. Compliance & Auditing

- **Immutable Audit Trail:** All policy evaluations, threat predictions, and containment actions are persisted with RFC 3339 UTC timestamps and SHA-256 traceable event identifiers.
- **Data Protection:** No cleartext customer payload data is inspected or stored; the gateway operates exclusively on flow metadata (IP, port, protocol, byte/packet statistics, timing).

