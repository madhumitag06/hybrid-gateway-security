<#
.SYNOPSIS
    Triggers a bounded on-demand packet capture on lab-router via telemetry-sensor.
#>
param(
    [string]$Scenario = "manual_capture",
    [int]$DurationSeconds = 12,
    [int]$MaxPackets = 500
)

$ErrorActionPreference = "Stop"

Write-Host "[capture-pcap] Capturing up to $MaxPackets packets for ${DurationSeconds}s on lab-router transit interfaces..." -ForegroundColor Cyan

docker exec hybrid-lab-telemetry-sensor python3 /app/sensor_service.py --capture-router $Scenario --duration $DurationSeconds --max-packets $MaxPackets
