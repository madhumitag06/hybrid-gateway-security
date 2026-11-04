<#
.SYNOPSIS
    Ingests the latest captured PCAP and simulated AWS VPC Flow Logs from the virtual lab into the Security Gateway API.
#>
$ErrorActionPreference = "Stop"

Write-Host "[ingest-capture] Submitting latest captured PCAP and simulated AWS VPC Flow Logs from telemetry-sensor to gateway-api..." -ForegroundColor Cyan

docker exec hybrid-lab-telemetry-sensor python3 /app/sensor_service.py --ingest-latest
