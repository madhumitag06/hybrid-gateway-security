#!/bin/sh
set -e

PEER_SUBNET="${PEER_SUBNET:-${REMOTE_SUBNET:-10.20.10.0/24}}"
ROUTER_IP="${ROUTER_IP:-${GATEWAY_IP:-10.10.10.2}}"

echo "[*] Initializing Traffic Generator on On-Premises Network (10.10.10.50)"
ip route del default 2>/dev/null || true
echo "[*] Installing static route to Cloud VPC (${PEER_SUBNET}) via Virtual Gateway (${ROUTER_IP})..."

if ip route replace "${PEER_SUBNET}" via "${ROUTER_IP}"; then
    echo "[+] Static route active: $(ip route show "${PEER_SUBNET}")"
else
    echo "[!] Warning: Failed to install static route."
fi

mkdir -p /var/lib/hybrid-lab/telemetry/pcaps
mkdir -p /var/lib/hybrid-lab/telemetry/flowlogs
mkdir -p /var/lib/hybrid-lab/telemetry/metadata

touch /tmp/traffic_gen_ready

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

echo "[+] traffic-generator ready in standby mode. Run scenarios via scripts/generate-traffic.ps1"
exec tail -f /dev/null
