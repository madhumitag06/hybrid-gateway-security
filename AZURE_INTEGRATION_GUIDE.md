# Microsoft Azure Integration Guide & Operations Manual

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Provider:** Microsoft Azure  
**Target Services:** Entra ID (Azure AD), Virtual Networks (VNet), Network Watcher Flow Logs (V1/V2), Network Security Groups (NSG)  

---

## 1. Overview & Architecture

The Azure Cloud Adapter integrates the Security Gateway into Microsoft Azure enterprise virtual networks. It parses Network Watcher Flow Log records (supporting both Version 1 and Version 2 flow tuples), extracts the canonical 9-feature ML schema, evaluates anomalies using authoritative XGBoost V2, and applies dynamic ingress deny security rules to Network Security Groups.

---

## 2. Authentication & Entra ID Federated Credentials

The integration utilizes Microsoft Entra ID Workload Identity Federation (OIDC) to enable keyless, secretless authentication.

### 2.1 Entra ID Application & Federated Credential Configuration
1. Register an App in Entra ID (e.g. `hybrid-sec-github-app`).
2. Add a Federated Identity Credential:
   - **Federated Credential Scenario:** Other issuer
   - **Issuer:** `https://token.actions.githubusercontent.com`
   - **Subject Identifier:** `repo:madhumitag06/hybrid-gateway-security:ref:refs/heads/main`
   - **Audience:** `api://AzureADTokenExchange`
3. Assign the Azure Application Service Principal the `Network Contributor` and `Reader` roles on the target Resource Group.

---

## 3. Azure Network Watcher Flow Logs (V1 & V2)

### 3.1 Flow Log V2 Tuple Format
Network Watcher Flow Logs Version 2 contain comma-separated flow tuples embedded inside JSON blobs:
`time,src_ip,dst_ip,src_port,dst_port,protocol,direction,decision,flow_state,packets_s2d,bytes_s2d,packets_d2s,bytes_d2s`

**Example V2 Tuple:**
`1586542485,10.50.10.15,10.50.10.2,49200,443,T,I,A,B,10,6500,15,9800`

**Field Breakdown:**
- `1586542485`: Unix epoch timestamp
- `10.50.10.15`: Source IP
- `10.50.10.2`: Destination IP
- `49200`: Source port
- `443`: Destination port
- `T`: Protocol (T = TCP, U = UDP)
- `I`: Flow direction (I = Inbound, O = Outbound)
- `A`: Security decision (A = Allow, D = Deny)
- `B`: Flow state (B = Begin, C = Continuing, E = End)
- `10`: Packets source to destination
- `6500`: Bytes source to destination
- `15`: Packets destination to source
- `9800`: Bytes destination to source

---

## 4. Telemetry Normalization & Parity

The `AzureTelemetryProvider` normalizes these tuples into `CanonicalFlowRecord`:
- Total Packets: $10 + 15 = 25$
- Total Bytes: $6500 + 9800 = 16,300$
- Duration: Derived from flow state timestamp intervals
- Connection Rate: Calculated without synthetic assumptions
- 9-Feature Vector: Extracted and evaluated via XGBoost V2
- Authentication Failures: Never inferred; strictly omitted

---

## 5. Containment via Network Security Groups (NSG)

When anomalous threats or malicious probes are confirmed:
- **Action:** Inserts a priority-100 Inbound Deny security rule in the target NSG:
  ```bash
  az network nsg rule create \
    --resource-group rg-hybrid-security \
    --nsg-name nsg-hybrid-gateway \
    --name Deny_Target_IP \
    --priority 100 \
    --direction Inbound \
    --access Deny \
    --protocol Tcp \
    --source-address-prefixes 203.0.113.88/32 \
    --destination-port-ranges "*"
  ```
- **Reversion:** The revert command is stored in PostgreSQL audit history:
  `az network nsg rule delete -g rg-hybrid-security --nsg-name nsg-hybrid-gateway -n Deny_Target_IP`

---

## 6. Troubleshooting

- **Symptom:** Connection probe reports `CONFIGURED_STANDBY`.
  - **Resolution:** Verify `azure_subscription_id` and `azure_tenant_id` are set. If using DefaultAzureCredential, ensure `AZURE_CLIENT_ID` and federated token paths are present.
- **Symptom:** Unparseable flow tuples.
  - **Resolution:** Verify Network Watcher is configured for Version 2 flow logs and JSON retention in Azure Storage is active.

