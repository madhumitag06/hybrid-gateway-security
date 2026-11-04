#!/bin/sh
set -e

NODE_NAME="${NODE_NAME:-workload}"
NODE_ZONE="${NODE_ZONE:-ON_PREMISE}"
PEER_SUBNET="${PEER_SUBNET:-${REMOTE_SUBNET:-}}"
ROUTER_IP="${ROUTER_IP:-${GATEWAY_IP:-}}"

echo "[*] Initializing hybrid lab node: ${NODE_NAME} (Zone: ${NODE_ZONE})"

# Remove default Docker bridge route so cross-subnet traffic can only traverse lab-router
ip route del default 2>/dev/null || true

# Configure explicit static route so cross-environment traffic MUST traverse lab-router
if [ -n "${PEER_SUBNET}" ] && [ -n "${ROUTER_IP}" ]; then
    echo "[*] Configuring static cross-zone route: ${PEER_SUBNET} via ${ROUTER_IP}"
    if ip route replace "${PEER_SUBNET}" via "${ROUTER_IP}"; then
        echo "[+] Static route installed: $(ip route show "${PEER_SUBNET}")"
    else
        echo "[!] Warning: Could not set static route (ensure CAP_NET_ADMIN is granted)."
    fi
fi

echo "[*] Active routing table for ${NODE_NAME}:"
ip route show

exec python3 /app/workload_server.py
