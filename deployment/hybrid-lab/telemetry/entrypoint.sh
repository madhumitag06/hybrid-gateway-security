#!/bin/sh
set -e

mkdir -p /var/lib/hybrid-lab/telemetry/pcaps
mkdir -p /var/lib/hybrid-lab/telemetry/flowlogs
mkdir -p /var/lib/hybrid-lab/telemetry/metadata

touch /tmp/telemetry_sensor_ready

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

echo "[*] Starting Telemetry Sensor & Simulated VPC Flow Log Exporter..."
exec python3 /app/sensor_service.py --daemon

