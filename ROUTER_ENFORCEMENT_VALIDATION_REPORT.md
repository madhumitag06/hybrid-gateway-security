# ROUTER ENFORCEMENT VALIDATION REPORT: LIVE DOCKER HYBRID LAB

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** Phase 6 — Live Router Netfilter Containment Validation  
**Date:** November 2026  
**Status:** 100% EMPIRICALLY VERIFIED INSIDE AUTHORIZED DOCKER LAB  
**Target Environment:** `hybrid-lab-router` (Alpine Linux Kernel Netfilter / iptables)  
**Control Agent:** `python3 /app/router_agent.py` on internal management interface `10.30.10.2:8099`  

---

## 1. Executive Summary

This report provides the empirical evidence for live data-plane router enforcement inside the authorized Docker hybrid lab container (`hybrid-lab-router`).

Rather than relying on mocked unit tests or theoretical API responses, the enforcement subsystem was evaluated directly against the Linux kernel's **Netfilter iptables tables** inside `hybrid-lab-router`:
- **Rule Creation (BLOCK):** Host-wide quarantine inserted into `HYBRID_LAB_CONTAINMENT` chain.
- **Rule Creation (RESTRICT):** Port-scoped service drop (`--dport 8080`) inserted without affecting other ports.
- **Idempotency Guarantee:** Re-applying duplicate rules increments internal reference counters without injecting duplicate iptables entries.
- **Management Plane Protection:** Attempts to block protected gateway interfaces (`10.30.10.2`, `10.10.10.1`, `10.20.10.1`) are strictly rejected.
- **Manual Revocation:** Immediate deletion of Netfilter rules upon administrative revocation.
- **Automated TTL Expiry Reaping:** Background daemon thread automatically cleans up expired rules after TTL expiration.

---

## 2. Docker Lab Router Architecture & Forwarding Topography

```
 [ On-Premises Subnet ]                   [ Virtual Hybrid Router ]                   [ Cloud VPC Subnet ]
   10.10.10.0/24                             hybrid-lab-router                          10.20.10.0/24
┌─────────────────────────┐               ┌────────────────────────┐               ┌────────────────────────┐
│ hybrid-lab-onprem-client│               │ eth0: Management Drop  │               │ hybrid-lab-cloud-client│
│ (10.10.10.10)           │◄─────────────►│ eth1: 10.10.10.1       │◄─────────────►│ (10.20.10.10)          │
│ hybrid-lab-traffic-gen  │               │ eth2: 10.20.10.1       │               │ hybrid-lab-cloud-web   │
│ (10.10.10.50)           │               │ eth3: 10.30.10.2 (Mgmt)│               │ (10.20.10.5)           │
└─────────────────────────┘               └───────────┬────────────┘               └────────────────────────┘
                                                      │
                                          ┌───────────▼────────────┐
                                          │ iptables FORWARD Chain │
                                          │ HYBRID_LAB_CONTAINMENT │
                                          └────────────────────────┘
```

### Netfilter Chain Structure:
All cross-subnet transit between On-Prem (`10.10.10.0/24`) and Cloud (`10.20.10.0/24`) traverses the router's `FORWARD` table:
1. `DROP` all traffic entering or exiting management subnet `10.30.10.0/24`.
2. Jump to `HYBRID_LAB_CONTAINMENT` chain for stateful security policy enforcement.
3. Jump to `HYBRID_LAB_TELEMETRY` chain for packet counter telemetry.
4. `ACCEPT` traffic with `ctstate RELATED,ESTABLISHED`.
5. Default policy: `DROP` non-conforming transit.

---

## 3. Live Empirical Test Results (6-Stage Test Suite)

Execution of container-internal validation script (`/tmp/validate_router_container.py`):

```
==================================================================
 LIVE DOCKER HYBRID-CLOUD ROUTER ENFORCEMENT VERIFICATION 
==================================================================

[1/6] Testing Rule Creation: BLOCK 10.10.10.99 (TTL: 4s)...
  -> Result: {'success': True, 'operation': 'ADD', 'installed_new_iptables_rule': True}
  -> Verified: iptables HYBRID_LAB_CONTAINMENT contains DROP for 10.10.10.99.

[2/6] Testing Idempotency: Re-applying BLOCK 10.10.10.99...
  -> Result: {'success': True, 'operation': 'ADD', 'installed_new_iptables_rule': False}
  -> Verified: Exactly 1 iptables rule present for 10.10.10.99 (Idempotency confirmed).

[3/6] Testing Targeted Port Restriction: RESTRICT 10.10.10.98 Port 8080...
  -> Result: {'success': True, 'operation': 'ADD', 'installed_new_iptables_rule': True}
  -> Verified: iptables contains port-scoped rule (-s 10.10.10.98 -p tcp --dport 8080 -j DROP).

[4/6] Testing Management Plane Protection (Safety Guardrail)...
  -> Verified: Protected / out-of-scope IP '10.30.10.2' was safely REJECTED.
  -> Verified: Protected / out-of-scope IP '10.10.10.1' was safely REJECTED.
  -> Verified: Protected / out-of-scope IP '10.20.10.1' was safely REJECTED.
  -> Verified: Protected / out-of-scope IP '127.0.0.1' was safely REJECTED.

[5/6] Testing Manual Revocation: REMOVE test-restrict-98...
  -> Result: {'success': True, 'operation': 'REMOVE', 'iptables_entries_removed': 1}
  -> Verified: 10.10.10.98 rule immediately expunged from iptables upon revocation.

[6/6] Testing Automatic TTL Expiry Reaping (Waiting 5s for test-block-99 to expire)...
  -> Verified: test-block-99 was automatically pruned upon TTL expiry by router reaper loop.

==================================================================
 STATUS: ALL 6 LIVE ROUTER ENFORCEMENT CHECKS PASSED (100% VERIFIED) 
==================================================================
```

---

## 4. Safety & Boundary Isolation Verification

To certify full adherence to operational security guidelines:

1. **Zero Windows Host Firewall Modification:**  
   All `iptables` operations execute strictly within the Linux network namespace of the Docker container `hybrid-lab-router`. Windows Filtering Platform (WFP) and Windows Defender Firewall remain 100% untouched.
2. **Zero Real AWS Cloud Infrastructure Changes:**  
   The hybrid cloud architecture is simulated entirely within isolated Docker bridge networks (`hybrid-lab-onprem-net`, `hybrid-lab-cloud-net`, `hybrid-lab-mgmt-net`). No AWS Security Groups, Network ACLs, or Route Tables were accessed.
3. **Protected Management Subnet Isolation:**  
   The router control agent binds exclusively to `10.30.10.2:8099` on the internal management bridge. The router kernel drops all forwarding into or out of `10.30.10.0/24`.
4. **Candidate Model Isolation:**  
   Candidate models operating in Shadow Mode do NOT possess access to `EnforcementService.execute_decision()`. Advisory predictions are physically incapable of emitting Netfilter commands.
5. **Fail-Safe Crash Recovery:**  
   If `router_agent.py` restarts or loses state, `EnforcementService.get_sandbox_adapter()` reconciles active non-expired database rules upon reconnection, ensuring continuous policy enforcement.

