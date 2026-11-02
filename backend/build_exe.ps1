# ==============================================================================
# Adaptive AI-Powered Security Gateway - Standalone Backend Build Script
# ==============================================================================
# Packages the complete FastAPI backend, ML artifacts, and database dependencies
# into a standalone Windows executable.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File backend/build_exe.ps1
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " Building Adaptive AI Security Gateway Standalone Executable" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$WorkspaceRoot = (Get-Item -Path "$PSScriptRoot\..").FullName
Set-Location -Path $WorkspaceRoot

$PyInstaller = "$WorkspaceRoot\ml\.venv\Scripts\pyinstaller.exe"
if (-not (Test-Path $PyInstaller)) {
    $PyInstaller = (Get-Command pyinstaller -ErrorAction SilentlyContinue).Source
}

if (-not $PyInstaller) {
    Write-Error "PyInstaller was not found. Please activate the virtual environment or install pyinstaller (pip install pyinstaller)."
    exit 1
}

Write-Host "[*] Workspace Root : $WorkspaceRoot" -ForegroundColor Gray
Write-Host "[*] PyInstaller Path : $PyInstaller" -ForegroundColor Gray
Write-Host "[*] Spec File        : AdaptiveSecurityGateway.spec" -ForegroundColor Gray

# Clean previous build artifacts
$DistPath = "$WorkspaceRoot\backend\executable"
$BuildTempPath = "$WorkspaceRoot\build"

# Safe backup of previous executable if present
$ExeDir = "$DistPath\AdaptiveSecurityGateway"
$BackupDir = "$DistPath\AdaptiveSecurityGateway_backup"

if (Test-Path $ExeDir) {
    Write-Host "[*] Creating safety backup of existing executable..." -ForegroundColor Gray
    if (Test-Path $BackupDir) { Remove-Item -Path $BackupDir -Recurse -Force }
    Copy-Item -Path $ExeDir -Destination $BackupDir -Recurse -Force
}

try {
    Write-Host "`n[*] Running PyInstaller build..." -ForegroundColor Yellow
    & $PyInstaller "$WorkspaceRoot\AdaptiveSecurityGateway.spec" --noconfirm --distpath $DistPath --workpath $BuildTempPath
} catch {
    Write-Host "`n[!] PyInstaller encountered an error during build!" -ForegroundColor Red
    if (Test-Path $BackupDir) {
        Write-Host "[!] Restoring previous executable from safety backup..." -ForegroundColor Yellow
        if (Test-Path $ExeDir) { Remove-Item -Path $ExeDir -Recurse -Force }
        Move-Item -Path $BackupDir -Destination $ExeDir -Force
    }
    throw $_
}

$ExePath = "$DistPath\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe"

if (Test-Path $ExePath) {
    if (Test-Path $BackupDir) {
        Remove-Item -Path $BackupDir -Recurse -Force
    }
    Write-Host "`n[✓] Standalone Executable Build Succeeded!" -ForegroundColor Green
    Write-Host "[✓] Executable Location: $ExePath" -ForegroundColor Green
    
    # Create top-level launcher runner in backend/executable/AdaptiveSecurityGateway.exe if needed or report exact path
    Write-Host "`nTo start the standalone backend, run from the project root:" -ForegroundColor Cyan
    Write-Host "  .\backend\executable\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe" -ForegroundColor White
} else {
    Write-Error "Build finished but executable was not found at $ExePath."
    exit 1
}
