<#
.SYNOPSIS
    Stops the Virtual Hybrid-Cloud Security Lab while preserving PostgreSQL and telemetry volumes.
.DESCRIPTION
    Runs `docker compose down` WITHOUT `-v` by default so that PostgreSQL security events,
    user accounts, policy audit history, and captured PCAP/FlowLog files persist across restarts.
#>
param(
    [switch]$PurgeVolumes = $false
)

$ErrorActionPreference = "Stop"
$LabDir = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $LabDir "compose.yaml"
$EnvFile = Join-Path $LabDir ".env"
if (-not (Test-Path $EnvFile)) {
    $EnvFile = Join-Path $LabDir ".env.example"
}

if ($PurgeVolumes) {
    Write-Warning "[hybrid-lab] -PurgeVolumes specified: Removing containers AND named volumes (hybrid_lab_pgdata, hybrid_lab_telemetry)."
    docker compose -f $ComposeFile --env-file $EnvFile down -v --remove-orphans
} else {
    Write-Host "[hybrid-lab] Stopping containers (preserving PostgreSQL & telemetry volumes)..." -ForegroundColor Cyan
    docker compose -f $ComposeFile --env-file $EnvFile down --remove-orphans
    Write-Host "[hybrid-lab] Stopped cleanly. Persistent data in hybrid_lab_pgdata is intact." -ForegroundColor Green
}

