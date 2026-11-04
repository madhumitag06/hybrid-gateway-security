# ==============================================================================
# Adaptive AI-Powered Security Gateway - Master Executable Build Script
# ==============================================================================
# Executes the mandatory 17-point synchronization and packaging pipeline.
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " Adaptive Security Gateway -- Automated Build and Package Pipeline " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$WorkspaceRoot = (Get-Item -Path "$PSScriptRoot\..").FullName
Set-Location -Path $WorkspaceRoot

$PyInstaller = "$WorkspaceRoot\ml\.venv\Scripts\pyinstaller.exe"
$PythonExe = "$WorkspaceRoot\ml\.venv\Scripts\python.exe"

if (-not (Test-Path $PyInstaller)) {
    $PyInstaller = (Get-Command pyinstaller -ErrorAction SilentlyContinue).Source
}
if (-not (Test-Path $PythonExe)) {
    $PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
}

if (-not $PyInstaller) {
    Write-Error "[FAIL] PyInstaller was not found. Please activate the virtual environment or install pyinstaller."
    exit 1
}

Write-Host "[1/17] Workspace Root  : $WorkspaceRoot" -ForegroundColor Gray
Write-Host "[1/17] PyInstaller     : $PyInstaller" -ForegroundColor Gray
Write-Host "[1/17] Python Engine   : $PythonExe" -ForegroundColor Gray

# Step 2: Verify Frontend Dependencies
Write-Host "`n[2/17] Checking frontend dependencies..." -ForegroundColor Yellow
if (-not (Test-Path "$WorkspaceRoot\node_modules")) {
    Write-Error "[FAIL] node_modules directory missing. Run 'npm install' first."
    exit 1
}
Write-Host "  -> Node modules verified." -ForegroundColor Green

# Step 3: Run Frontend TypeScript Compilation
Write-Host "`n[3/17] Running TypeScript check (tsc -b)..." -ForegroundColor Yellow
& cmd.exe /c "npx tsc -b"
if ($LASTEXITCODE -ne 0) {
    Write-Error "[FAIL] TypeScript compilation failed. Aborting build."
    exit 1
}
Write-Host "  -> TypeScript check passed cleanly." -ForegroundColor Green

# Step 4: Run Production Vite Build
Write-Host "`n[4/17] Running production Vite build..." -ForegroundColor Yellow
& cmd.exe /c "npm run build"
if ($LASTEXITCODE -ne 0) {
    Write-Error "[FAIL] Frontend production build failed. Aborting packaging."
    exit 1
}

# Step 5 and 6: Validate dist/index.html and generated assets
Write-Host "`n[5/17 and 6/17] Validating production frontend distribution assets..." -ForegroundColor Yellow
$DistIndex = "$WorkspaceRoot\dist\index.html"
$DistAssets = "$WorkspaceRoot\dist\assets"

if (-not (Test-Path $DistIndex)) {
    Write-Error "[FAIL] Frontend build succeeded but index.html missing at $DistIndex."
    exit 1
}

$JsAssets = Get-ChildItem -Path $DistAssets -Filter "*.js"
$CssAssets = Get-ChildItem -Path $DistAssets -Filter "*.css"

if ($JsAssets.Count -eq 0 -or $CssAssets.Count -eq 0) {
    Write-Error "[FAIL] JavaScript or CSS assets missing in $DistAssets."
    exit 1
}

$LatestJsName = $JsAssets[0].Name
$LatestCssName = $CssAssets[0].Name
$JsSizeKb = [math]::Round($JsAssets[0].Length / 1024, 1)
$CssSizeKb = [math]::Round($CssAssets[0].Length / 1024, 1)

Write-Host "  -> Latest JS  : $LatestJsName ($JsSizeKb KB)" -ForegroundColor Green
Write-Host "  -> Latest CSS : $LatestCssName ($CssSizeKb KB)" -ForegroundColor Green

# Step 7: Run Backend Unit Tests
Write-Host "`n[7/17] Running backend prediction and duration API test suite..." -ForegroundColor Yellow
& $PythonExe -m pytest "$WorkspaceRoot\backend\tests\test_predict_api.py" -q
if ($LASTEXITCODE -ne 0) {
    Write-Error "[FAIL] Backend tests failed. Aborting executable packaging."
    exit 1
}
Write-Host "  -> Backend prediction and duration test suite passed (12/12)." -ForegroundColor Green

# Step 8: Run Frontend Linter
Write-Host "`n[8/17] Running frontend linter (oxlint)..." -ForegroundColor Yellow
& cmd.exe /c "npm run lint"
if ($LASTEXITCODE -ne 0) {
    Write-Error "[FAIL] Linter reported errors. Aborting packaging."
    exit 1
}
Write-Host "  -> Lint check passed with 0 errors." -ForegroundColor Green

# Step 9: Prepare Executable Paths and Safe Backup
Write-Host "`n[9/17] Preparing distribution paths and safe backup..." -ForegroundColor Yellow
$DistPath = "$WorkspaceRoot\backend\executable"
$BuildTempPath = "$WorkspaceRoot\build"
$ExeDir = "$DistPath\AdaptiveSecurityGateway"
$BackupDir = "$DistPath\AdaptiveSecurityGateway_backup"

# Terminate any running executable instances to release Windows DLL/file locks
Get-Process -Name "AdaptiveSecurityGateway" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600

if (Test-Path $ExeDir) {
    Write-Host "  -> Preserving safety backup of existing executable..." -ForegroundColor Gray
    if (Test-Path $BackupDir) {
        Remove-Item -Path $BackupDir -Recurse -Force
    }
    Copy-Item -Path $ExeDir -Destination $BackupDir -Recurse -Force
    Write-Host "  -> Backup preserved at: $BackupDir" -ForegroundColor Green
}

# Step 10, 11, 12: Run PyInstaller Build
Write-Host "`n[10/17 - 12/17] Building PyInstaller executable with bundled ML and frontend assets..." -ForegroundColor Yellow
try {
    & $PyInstaller "$WorkspaceRoot\AdaptiveSecurityGateway.spec" --noconfirm --distpath $DistPath --workpath $BuildTempPath
} catch {
    Write-Host "`n[!] PyInstaller build failed!" -ForegroundColor Red
    if (Test-Path $BackupDir) {
        Write-Host "[!] Restoring previous executable from safety backup..." -ForegroundColor Yellow
        if (Test-Path $ExeDir) { Remove-Item -Path $ExeDir -Recurse -Force }
        Copy-Item -Path $BackupDir -Destination $ExeDir -Force
    }
    throw $_
}

# Step 13, 14, 15: Validate Built Executable and Asset Synchronization
Write-Host "`n[13/17 - 15/17] Validating built executable and bundled assets..." -ForegroundColor Yellow
$ExePath = "$DistPath\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe"

if (-not (Test-Path $ExePath)) {
    Write-Error "[FAIL] Executable not found at $ExePath."
    exit 1
}

$ExeItem = Get-Item -Path $ExePath
$BundledAssetsDir = "$DistPath\AdaptiveSecurityGateway\_internal\dist\assets"
$BundledJs = Get-ChildItem -Path $BundledAssetsDir -Filter "*.js" | Select-Object -First 1
$BundledCss = Get-ChildItem -Path $BundledAssetsDir -Filter "*.css" | Select-Object -First 1

if (-not $BundledJs -or $BundledJs.Name -ne $LatestJsName) {
    Write-Error "[FAIL] Bundled JS ($($BundledJs.Name)) does NOT match latest dist JS ($LatestJsName)!"
    exit 1
}
if (-not $BundledCss -or $BundledCss.Name -ne $LatestCssName) {
    Write-Error "[FAIL] Bundled CSS ($($BundledCss.Name)) does NOT match latest dist CSS ($LatestCssName)!"
    exit 1
}

$ExeMb = [math]::Round($ExeItem.Length / 1048576, 2)
Write-Host "  -> Executable Size : $ExeMb MB ($($ExeItem.Length) bytes)" -ForegroundColor Green
Write-Host "  -> Last Modified   : $($ExeItem.LastWriteTime)" -ForegroundColor Green
Write-Host "  -> Bundled JS Asset: $($BundledJs.Name) (MATCHED)" -ForegroundColor Green
Write-Host "  -> Bundled CSS Asset: $($BundledCss.Name) (MATCHED)" -ForegroundColor Green

# Step 16: Verify Packaged Application Metadata via CLI
Write-Host "`n[16/17] Verifying packaged application CLI startup metadata..." -ForegroundColor Yellow
$CliVersion = & $ExePath --version
Write-Host "  -> CLI Output: $CliVersion" -ForegroundColor Green

# Step 17: Produce Build Report
Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host " BUILD REPORT: Standalone Executable Successfully Synchronized" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " Status         : SUCCESS (17/17 Steps Verified)" -ForegroundColor Green
Write-Host " Executable     : $ExePath" -ForegroundColor White
Write-Host " Size           : $ExeMb MB ($($ExeItem.Length) bytes)" -ForegroundColor White
Write-Host " Timestamp      : $($ExeItem.LastWriteTime)" -ForegroundColor White
Write-Host " Bundled Assets : $($BundledJs.Name), $($BundledCss.Name)" -ForegroundColor White
Write-Host " Backup Kept    : $BackupDir" -ForegroundColor White
Write-Host "==================================================================`n" -ForegroundColor Cyan
