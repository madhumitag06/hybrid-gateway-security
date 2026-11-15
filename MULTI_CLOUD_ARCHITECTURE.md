# Multi-Cloud Architecture & Abstraction Specification

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Version:** 2.0.0-Enterprise  
**Primary Engine:** Authoritative XGBoost V2 (9-Feature Canonical Schema)  
**Rollback Standby:** Random Forest Baseline (10-Feature Schema)  
**Supported Providers:** Amazon Web Services (AWS), Google Cloud Platform (GCP / Google Builders Hub), Microsoft Azure, and Docker Hybrid Simulation Lab  

---

## 1. Executive Architecture Overview

The Adaptive AI-Powered Security Gateway has transitioned from an internal Docker-based prototype into an enterprise-grade, cloud-agnostic security architecture capable of ingesting network flow logs, detecting sophisticated threats via machine learning, evaluating policy decisions, and executing automated containment across Amazon Web Services, Google Cloud Platform, Microsoft Azure, and on-premises/containerized infrastructure.

```
                              ┌────────────────────────────────────────────────────────┐
                              │            ENTERPRISE SECOPS DASHBOARD                 │
                              │           React + TypeScript + Tailwind UI             │
                              └───────────────────────────┬────────────────────────────┘
                                                          │ REST / SSE
                                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       FASTAPI SECURITY GATEWAY CORE                                             │
│                                                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                                       CLOUD ABSTRACTION LAYER                                           │   │
│   │                                                                                                         │   │
│   │   ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐   ┌───────────────────┐   │   │
│   │   │     AWS Adapter     │   │     GCP Adapter     │   │    Azure Adapter    │   │ Docker Lab Adapter│   │   │
│   │   │  • STS AssumeRole   │   │  • Workload Identity│   │  • Entra ID OIDC    │   │ • Local Router    │   │   │
│   │   │  • VPC Flow Logs V2 │   │  • Cloud Logging VPC│   │  • NSG Flow Logs V2 │   │ • Raw PCAP/Stream │   │   │
│   │   │  • Security Group/ACL│  │  • Cloud Firewalls  │   │  • NSG Deny Rules   │   │ • iptables/Routes │   │   │
│   │   └──────────┬──────────┘   └──────────┬──────────┘   └──────────┬──────────┘   └─────────┬─────────┘   │   │
│   └──────────────┼─────────────────────────┼─────────────────────────┼────────────────────────┼─────────────┘   │
│                  ▼                         ▼                         ▼                        ▼                 │
│   ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                                   CANONICAL TELEMETRY NORMALIZER                                        │   │
│   │    Enforces strict mathematical 9-feature schema without synthetic authentication failure dependency    │   │
│   │    [packet_count, byte_count, duration, conn_rate, dst_port, unique_dst_ports, bps, pps, avg_pkt_size]  │   │
│   └────────────────────────────────────────────────────┬────────────────────────────────────────────────────┘   │
│                                                        │ 9-feature Vector                                       │
│                                                        ▼                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                                      THREAT PREDICTION ENGINE                                           │   │
│   │   Authoritative Primary: XGBoost V2 (6.49M trained records) │ Standby Rollback: Random Forest           │   │
│   │   Model Registry State: Zero-downtime hot promotion, atomic rollback, SHAP explainability caching       │   │
│   └────────────────────────────────────────────────────┬────────────────────────────────────────────────────┘   │
│                                                        │ Threat Level & Risk Score                              │
│                                                        ▼                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                                  ADAPTIVE POLICY & CONTAINMENT ENGINE                                   │   │
│   │   Context-aware evaluation, stateful rate-limiting, dry-run safety gates, and dynamic firewall pushes   │   │
│   └────────────────────────────────────────────────────┬────────────────────────────────────────────────────┘   │
│                                                        │ Security Events & Audit Trail                          │
│                                                        ▼                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                                 POSTGRESQL MULTI-CLOUD DATA LAYER                                       │   │
│   │   CloudAccountModel │ CloudResourceModel │ SecurityEventModel │ PolicyAuditLogModel │ RetrainingFeedback    │   │
│   └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Abstraction Layer (`backend/app/cloud/`)

To ensure complete provider independence and prevent vendor lock-in, the gateway enforces a four-tier object-oriented abstraction hierarchy:

### 2.1 Interface Contracts (`backend/app/cloud/interfaces/`)
- **`BaseCloudProviderAdapter`**: Abstract master contract governing all provider operations:
  - `validate_configuration() -> Tuple[bool, str]`: Static syntax validation.
  - `check_connection() -> Dict[str, Any]`: Live connectivity and credentials check.
  - `get_capabilities() -> CloudCapabilitiesSchema`: Feature flag and telemetry matrix.
  - `list_network_resources() -> List[CloudResourceSchema]`: VPC, subnet, gateway, and security group inventory.
  - `get_health() -> Dict[str, Any]`: Real-time operational health.
- **`BaseTelemetryProvider`**: Defines flow log extraction, streaming, and line/tuple normalization into `CanonicalFlowRecord`.
- **`BaseCloudEnforcementProvider`**: Defines containment primitives (`apply_containment()`, `revoke_containment()`, `list_active_containments()`), strictly bounded by dry-run safeguards.
- **`BaseCloudIdentityProvider`**: Defines keyless identity verification (`get_caller_identity()`, `get_federation_metadata()`).

### 2.2 Concrete Provider Adapters (`backend/app/cloud/adapters/`)
1. **`AwsCloudAdapter`**: Implements STS AssumeRole, IAM caller identity verification, VPC Flow Log Version 2 whitespace-delimited parsing, Security Group isolation, and Network ACL entry manipulation.
2. **`GcpCloudAdapter`**: Tailored for Google Builders Hub. Implements Google Workload Identity Federation (OIDC), Cloud Logging VPC flow logs JSON parsing, Cloud Router/NAT discovery, and high-priority Cloud Firewall deny policies.
3. **`AzureCloudAdapter`**: Implements Microsoft Entra ID federated credentials, Azure Network Watcher NSG Flow Log Version 1 and 2 comma-separated tuple parsing, and priority-100 NSG Inbound security deny rules.
4. **`DockerLabCloudAdapter`**: Preserves the existing containerized hybrid lab environment as a first-class provider adapter, mapping on-prem (`10.10.10.0/24`), cloud (`10.20.10.0/24`), and router (`10.30.10.2:8099`) topologies directly into the unified data plane.

### 2.3 Core Management Services (`backend/app/cloud/services/`)
- **`TelemetryNormalizer`**: Translates disparate provider log formats into the canonical 9-feature XGBoost V2 input schema. Computes throughput, packet rates, and stateful destination port diversity per source IP.
- **`TelemetryCheckpointService`**: Manages persistent ingestion checkpoints (`CloudTelemetryCheckpointModel`), deduplication filter caches (`DeduplicationCache`), and batch ingestion audit records (`CloudTelemetryIngestionModel`).
- **`CloudRegistry`**: Coordinates database-backed persistence of cloud accounts (`CloudAccountModel`) and network resources (`CloudResourceModel`), ensuring complete secret redaction.
- **`CloudConnectionManager`**: Thread-safe adapter factory managing adapter lifecycle, caching, and health diagnostics.
- **`CloudHealthMonitor`**: Real-time aggregator computing multi-cloud readiness, provider latencies, and degradation alerts.

---

## 3. Strict 9-Feature Normalization & Parity

During the Big Data training and audit phases, synthetic `failed_auth_count` was identified as an unobservable, synthetic feature at network layers L3/L4. The authoritative XGBoost V2 model was retrained on 6.49M real-world intrusion records across 9 genuine network flow features.

The Multi-Cloud Telemetry Normalizer strictly enforces this schema:

| Feature Name | Source | Mathematical Definition | Valid Range |
| :--- | :--- | :--- | :--- |
| `packet_count` | Observed | Total flow packet count | $\ge 1$ |
| `byte_count` | Observed | Total payload bytes transferred | $\ge 64$ |
| `duration` | Observed / Derived | Flow elapsed time in seconds | $\ge 0.001\text{ s}$ |
| `conn_rate` | Derived | $\text{packet\_count} / \max(\text{duration}, 0.01)$ | $[0.1, 500.0]$ |
| `dst_port` | Observed | Targeted destination port | $[1, 65535]$ |
| `unique_dst_ports` | Stateful Derived | Unique ports targeted by source IP | $\ge 1$ |
| `bytes_per_sec` | Derived | $\text{byte\_count} / \max(\text{duration}, 0.001)$ | $\ge 0.0$ |
| `packets_per_sec` | Derived | $\text{packet\_count} / \max(\text{duration}, 0.001)$ | $\ge 0.0$ |
| `avg_packet_size` | Derived | $\text{byte\_count} / \max(\text{packet\_count}, 1)$ | $\ge 0.0$ |

**Strict Telemetry Parity Guarantee:** In accordance with production security policies, `failed_auth_count` is NEVER synthesized, inferred, or generated from flow logs across AWS, GCP, Azure, or Docker Lab.

---

## 4. Security & Secret Redaction Guarantee

The gateway enforces zero-trust secret management:
1. **No Static Credentials in Code or Database:** Cloud credentials, API keys, and client secrets are never committed to Git, hardcoded, or stored in PostgreSQL.
2. **Secret Redaction Filter:** The `CloudRegistry` and API serializers sanitize all account metadata, stripping potential credential keys before saving or returning account information.
3. **OpenID Connect (OIDC) Workload Identity:** Production CI/CD pipelines and runtime workloads authenticate via cryptographic token exchange (GitHub Actions OIDC to AWS STS, GCP WIF, and Azure Entra ID).
4. **Dry-Run Containment Safeguards:** Live cloud containment defaults to safe simulated dry-runs (`dry_run=True`), requiring explicit administrator authorization before modifying active security groups, firewall rules, or NSGs.

