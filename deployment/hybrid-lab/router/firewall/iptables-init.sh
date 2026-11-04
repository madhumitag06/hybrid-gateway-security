#!/bin/sh
set -e

echo "=================================================================="
echo " Virtual Hybrid-Cloud Gateway Router — Isolated Firewall Setup"
echo "=================================================================="

if [ -f /run/hybrid-router/interfaces.env ]; then
    . /run/hybrid-router/interfaces.env
fi

# Flush existing filter rules inside lab-router's isolated network namespace
iptables -F FORWARD || true
iptables -N HYBRID_LAB_CONTAINMENT 2>/dev/null || iptables -F HYBRID_LAB_CONTAINMENT
iptables -N HYBRID_LAB_TELEMETRY 2>/dev/null || iptables -F HYBRID_LAB_TELEMETRY

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
iptables -A HYBRID_LAB_TELEMETRY -s 10.20.10.0/24 -d 10.10.10.0/24 -m comment --comment "CLOUD_TO_ON_PREM" -j RETURN

# 4. Permit established/related and authorized cross-zone forwarding between 10.10.10.0/24 and 10.20.10.0/24
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -s 10.10.10.0/24 -d 10.20.10.0/24 -j ACCEPT
iptables -A FORWARD -s 10.20.10.0/24 -d 10.10.10.0/24 -j ACCEPT

# 5. Default drop for any unexpected non-lab transit
iptables -A FORWARD -j DROP

echo "[+] Isolated lab-router iptables FORWARD policy initialized:"
iptables -L FORWARD -v -n

