#!/bin/sh
set -e

echo "=================================================================="
echo " Virtual Hybrid-Cloud Gateway Router — Routing Initialization"
echo "=================================================================="

# Verify IPv4 forwarding is enabled (configured via Compose sysctls, with runtime fallback)
CURRENT_FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
if [ "${CURRENT_FWD}" != "1" ]; then
    echo "[*] Enabling net.ipv4.ip_forward=1..."
    sysctl -w net.ipv4.ip_forward=1 || echo "[!] Warning: sysctl write requires Compose sysctls or CAP_NET_ADMIN"
fi

# Disable ICMP redirects and reverse-path filtering so multi-subnet routing works deterministically
sysctl -w net.ipv4.conf.all.send_redirects=0 2>/dev/null || true
sysctl -w net.ipv4.conf.default.send_redirects=0 2>/dev/null || true
sysctl -w net.ipv4.conf.all.accept_redirects=0 2>/dev/null || true
sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null || true

# Detect interfaces by assigned subnet IPs
ONPREM_IF=$(ip -o -4 addr show | awk '/10\.10\.10\.2\// {print $2}' | head -n 1)
CLOUD_IF=$(ip -o -4 addr show | awk '/10\.20\.10\.2\// {print $2}' | head -n 1)
MGMT_IF=$(ip -o -4 addr show | awk '/10\.30\.10\.2\// {print $2}' | head -n 1)

echo "[+] Detected On-Premises Interface (10.10.10.2/24): ${ONPREM_IF:-unknown}"
echo "[+] Detected Cloud VPC Interface   (10.20.10.2/24): ${CLOUD_IF:-unknown}"
echo "[+] Detected Management Interface  (10.30.10.2/24): ${MGMT_IF:-unknown}"

mkdir -p /run/hybrid-router
cat <<EOF > /run/hybrid-router/interfaces.env
ONPREM_IF=${ONPREM_IF}
CLOUD_IF=${CLOUD_IF}
MGMT_IF=${MGMT_IF}
EOF

echo "[*] Active Router Interfaces & Routes:"
ip -4 addr show
ip route show

