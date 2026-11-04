<#
.SYNOPSIS
    Displays the live health, routing tables, firewall rules, and telemetry status of the Virtual Hybrid Lab.
#>
$ErrorActionPreference = "Continue"
$LabDir = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $LabDir "compose.yaml"
$EnvFile = Join-Path $LabDir ".env"
if (-not (Test-Path $EnvFile)) {
    $EnvFile = Join-Path $LabDir ".env.example"
}

Write-Host "=== [1/4] Container Topology & Health Status ===" -ForegroundColor Cyan
docker compose -f $ComposeFile --env-file $EnvFile ps

Write-Host "`n=== [2/4] Virtual Router (lab-router) Interfaces & Routing Table ===" -ForegroundColor Cyan
docker exec hybrid-lab-router ip -brief addr
docker exec hybrid-lab-router ip route

Write-Host "`n=== [3/4] Virtual Router Isolated Firewall Chain (HYBRID_LAB_CONTAINMENT) ===" -ForegroundColor Cyan
docker exec hybrid-lab-router iptables -L HYBRID_LAB_CONTAINMENT -v -n

Write-Host "`n=== [4/4] Telemetry Sensor Status & Captured Files ===" -ForegroundColor Cyan
docker exec hybrid-lab-telemetry-sensor ls -lh /var/lib/hybrid-lab/telemetry/pcaps /var/lib/hybrid-lab/telemetry/flowlogs

