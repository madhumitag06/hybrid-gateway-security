<#
.SYNOPSIS
    Triggers a bounded network traffic scenario across the Virtual Hybrid-Cloud boundary.
.PARAMETER Scenario
    Scenario to execute: benign | port_scan | traffic_spike | suspicious_transfer | containment | all
#>
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("benign", "port_scan", "brute_force", "traffic_spike", "suspicious_transfer", "containment", "all")]
    [string]$Scenario = "benign"
)

$ErrorActionPreference = "Stop"

Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host " Executing Hybrid-Cloud Traffic Scenario: $Scenario" -ForegroundColor Cyan
Write-Host " Source Zone : onprem_net (10.10.10.0/24)"
Write-Host " Transit Hop : lab-router (10.10.10.2 -> 10.20.10.2)"
Write-Host " Target Zone : cloud_vpc_net (10.20.10.0/24)"
Write-Host "=========================================================================" -ForegroundColor Cyan

docker exec hybrid-lab-traffic-generator python /app/run_scenario.py --scenario $Scenario

