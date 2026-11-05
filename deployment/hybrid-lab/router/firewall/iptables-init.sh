#!/bin/sh
set -e

echo "=================================================================="
echo " Virtual Hybrid-Cloud Gateway Router — Isolated Firewall Setup"
echo "=================================================================="

# ==============================================================================
# STRICT SAFETY GUARD: Verify Isolated Container Network Namespace
# Permanently prevents accidental execution in host or unintended namespaces.
# ==============================================================================
# 1. Host bridge presence check: If host bridges (docker0, br-*) exist, this is the host namespace!
if ip -br link show 2>/dev/null | grep -qE "docker0|br-[0-9a-f]{12}"; then
    echo "[CRITICAL FATAL ERROR] Host bridge interfaces detected in current network namespace!"
    echo "[CRITICAL FATAL ERROR] Refusing to run iptables initialization: this script MUST NEVER execute on the host."
    exit 1
fi

# 2. Hostname check: The router container hostname must match lab-router or have ROUTER_ONPREM_IP
CONTAINER_HOST=$(hostname 2>/dev/null || echo "")
if [ "${CONTAINER_HOST}" != "lab-router" ] && [ -z "${ROUTER_ONPREM_IP}" ]; then
    echo "[CRITICAL FATAL ERROR] Hostname '${CONTAINER_HOST}' is not 'lab-router' and ROUTER_ONPREM_IP is unset."
    echo "[CRITICAL FATAL ERROR] Refusing to run iptables commands in unverified namespace."
    exit 1
fi

# 3. Router interface IP check: At least one router lab IP (10.10.10.2, 10.20.10.2, 10.30.10.2) must exist
HAS_ROUTER_IP=$(ip -o -4 addr show 2>/dev/null | grep -E "10\.(10|20|30)\.10\.2" | head -n 1 || true)
if [ -z "${HAS_ROUTER_IP}" ]; then
    echo "[CRITICAL FATAL ERROR] No router virtual lab IP (10.10.10.2 / 10.20.10.2 / 10.30.10.2) found on any interface!"
    echo "[CRITICAL FATAL ERROR] Network namespace does not match lab-router. Aborting firewall initialization."
    exit 1
fi

echo "[+] Verified isolated router network namespace (${CONTAINER_HOST}). Proceeding safely."

if [ -f /run/hybrid-router/interfaces.env ]; then
    . /run/hybrid-router/interfaces.env
fi

# Initialize dedicated chains safely (never flush all FORWARD indiscriminately)
iptables -N HYBRID_LAB_CONTAINMENT 2>/dev/null || iptables -F HYBRID_LAB_CONTAINMENT
iptables -N HYBRID_LAB_TELEMETRY 2>/dev/null || iptables -F HYBRID_LAB_TELEMETRY

# Clean previous router rules to guarantee idempotency on restarts
iptables -D FORWARD -s 10.30.10.0/24 -j DROP 2>/dev/null || true
iptables -D FORWARD -d 10.30.10.0/24 -j DROP 2>/dev/null || true
if [ -n "${MGMT_IF}" ]; then
    iptables -D FORWARD -i "${MGMT_IF}" -j DROP 2>/dev/null || true
    iptables -D FORWARD -o "${MGMT_IF}" -j DROP 2>/dev/null || true
fi
iptables -D FORWARD -s 10.10.10.0/24 -d 10.20.10.0/24 -j HYBRID_LAB_CONTAINMENT 2>/dev/null || true
iptables -D FORWARD -s 10.20.10.0/24 -d 10.10.10.0/24 -j HYBRID_LAB_CONTAINMENT 2>/dev/null || true
iptables -D FORWARD -s 10.10.10.0/24 -d 10.20.10.0/24 -j HYBRID_LAB_TELEMETRY 2>/dev/null || true
iptables -D FORWARD -s 10.20.10.0/24 -d 10.10.10.0/24 -j HYBRID_LAB_TELEMETRY 2>/dev/null || true
iptables -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -s 10.10.10.0/24 -d 10.20.10.0/24 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -s 10.20.10.0/24 -d 10.10.10.0/24 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -j DROP 2>/dev/null || true

# 1. Strict Management Plane Isolation: NEVER forward packets to or from mgmt_net (10.30.10.0/24)
iptables -A FORWARD -s 10.30.10.0/24 -j DROP
iptables -A FORWARD -d 10.30.10.0/24 -j DROP
if [ -n "${MGMT_IF}" ]; then
    iptables -A FORWARD -i "${MGMT_IF}" -j DROP
    iptables -A FORWARD -o "${MGMT_IF}" -j DROP
fi

# 2. Pass all On-Prem <-> Cloud VPC transit traffic through the isolated containment & telemetry chains
iptables -A FORWARD -s 10.10.10.0/24 -d 10.20.10.0/24 -j HYBRID_LAB_CONTAINMENT
iptables -A FORWARD -s 10.20.10.0/24 -d 10.10.10.0/24 -j HYBRID_LAB_CONTAINMENT

iptables -A FORWARD -s 10.10.10.0/24 -d 10.20.10.0/24 -j HYBRID_LAB_TELEMETRY
iptables -A FORWARD -s 10.20.10.0/24 -d 10.10.10.0/24 -j HYBRID_LAB_TELEMETRY

# 3. Telemetry accounting rules in HYBRID_LAB_TELEMETRY
iptables -A HYBRID_LAB_TELEMETRY -s 10.10.10.0/24 -d 10.20.10.0/24 -m comment --comment "ON_PREM_TO_CLOUD" -j RETURN
iptables -A HYBRID_LAB_TELEMETRY -s 20.10.10.0/24 -d 10.10.10.0/24 -m comment --comment "CLOUD_TO_ON_PREM" -j RETURN 2>/dev/null || \
iptables -A HYBRID_LAB_TELEMETRY -s 10.20.10.0/24 -d 10.10.10.0/24 -m comment --comment "CLOUD_TO_ON_PREM" -j RETURN

# 4. Permit established/related and authorized cross-zone forwarding between 10.10.10.0/24 and 10.20.10.0/24
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -s 10.10.10.0/24 -d 10.20.10.0/24 -j ACCEPT
iptables -A FORWARD -s 10.20.10.0/24 -d 10.10.10.0/24 -j ACCEPT

# 5. Default drop for any unexpected non-lab transit
iptables -A FORWARD -j DROP

echo "[+] Isolated lab-router iptables FORWARD policy initialized safely:"
iptables -L FORWARD -v -n
