#!/bin/sh
set -e

mkdir -p /var/lib/hybrid-lab/telemetry/pcaps
mkdir -p /var/lib/hybrid-lab/telemetry/flowlogs
mkdir -p /var/lib/hybrid-lab/telemetry/metadata

/app/routing/configure-routes.sh
/app/firewall/iptables-init.sh

echo "[*] Starting Virtual Hybrid Router Control & Telemetry Agent on 10.30.10.2:8099..."
exec python3 /app/router_agent.py

