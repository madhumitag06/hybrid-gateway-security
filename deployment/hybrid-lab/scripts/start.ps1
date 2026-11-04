<#
.SYNOPSIS
    Starts the isolated Docker-based Virtual Hybrid-Cloud Security Lab.
.DESCRIPTION
    Builds and starts the 3-network hybrid topology (onprem_net, cloud_vpc_net, mgmt_net),
    the virtual Linux router (lab-router), workload containers, telemetry sensor,
    PostgreSQL persistence volume, and the Adaptive AI Security Gateway.
#>
param(
    [switch]$EnableLabEnforcement = $false,
    [switch]$NoBuild = $false
)

$ErrorActionPreference = "Stop"
$LabDir = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $LabDir "compose.yaml"
$EnvFile = Join-Path $LabDir ".env"
$EnvExample = Join-Path $LabDir ".env.example"

if (-not (Test-Path $EnvFile)) {
    Write-Host "[hybrid-lab] Initializing .env from .env.example..." -ForegroundColor Cyan
    Copy-Item $EnvExample $EnvFile
}

if ($EnableLabEnforcement) {
    $env:LAB_ENFORCEMENT_ENABLED = "true"
    Write-Host "[hybrid-lab] Opt-in Virtual Router iptables Enforcement ENABLED for this session." -ForegroundColor Yellow
}

Write-Host "[hybrid-lab] Starting Virtual Hybrid-Cloud Security Environment..." -ForegroundColor Green
if ($NoBuild) {
    docker compose -f $ComposeFile --env-file $EnvFile up -d
} else {
    docker compose -f $ComposeFile --env-file $EnvFile up --build -d
}

$composeExitCode = $LASTEXITCODE
if ($composeExitCode -ne 0) {
    Write-Host ""
    Write-Host "=========================================================================" -ForegroundColor Red
    Write-Host " [hybrid-lab] ERROR: Docker Compose failed with exit code $composeExitCode." -ForegroundColor Red
    Write-Host " Virtual Hybrid-Cloud Lab was NOT started. Inspect build/compose logs above." -ForegroundColor Red
    Write-Host "=========================================================================" -ForegroundColor Red
    exit $composeExitCode
}

# Ensure Docker Engine 28+/29 br_netfilter permits intra-bridge L2 forwarding to lab-router
$onpremId = (docker network inspect hybrid_lab_onprem_net --format "{{.Id}}" 2>$null)
$cloudId  = (docker network inspect hybrid_lab_cloud_vpc_net --format "{{.Id}}" 2>$null)
if ($onpremId -and $cloudId) {
    $brOnprem = "br-" + $onpremId.Substring(0, 12)
    $brCloud  = "br-" + $cloudId.Substring(0, 12)
    docker run --rm --net=host --cap-add=NET_ADMIN --entrypoint sh hybrid-security-lab-lab-router -c "iptables -C DOCKER-USER -i $brOnprem -o $brOnprem -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 1 -i $brOnprem -o $brOnprem -j ACCEPT; iptables -C DOCKER-USER -i $brCloud -o $brCloud -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER 2 -i $brCloud -o $brCloud -j ACCEPT" 2>$null
}

Write-Host ""
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host " Adaptive AI Security Gateway - Virtual Hybrid-Cloud Lab Started" -ForegroundColor Cyan
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "  On-Premises Private Subnet : 10.10.10.0/24 (Gateway: 10.10.10.2)"
Write-Host "  Simulated Cloud VPC Subnet : 10.20.10.0/24 (Gateway: 10.20.10.2)"
Write-Host "  Management / Control Plane : 10.30.10.0/24"
Write-Host "  Frontend Dashboard         : http://localhost:5173"
Write-Host "  Security Gateway API       : http://localhost:8000/docs"
Write-Host "=========================================================================" -ForegroundColor Cyan

