# BYE BAC CLI Setup Script for Windows PowerShell
# This script adds byebac to your PATH so you can run it from anywhere
# Purpose: provide permanent/semi-permanent command setup for `byebac`.
# Usage: .\scripts\SETUP_CLI.ps1
# Verify: byebac /help

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BatFile = Join-Path $ProjectRoot "byebac.bat"
$Ps1File = Join-Path $ProjectRoot "byebac.ps1"

Write-Host ""
Write-Host "BYE BAC CLI Setup" -ForegroundColor Cyan
Write-Host ""

# Check if files exist
if (-not (Test-Path $BatFile)) {
    Write-Host "Error: byebac.bat not found." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $Ps1File)) {
    Write-Host "Error: byebac.ps1 not found." -ForegroundColor Red
    exit 1
}

Write-Host "Installation Directory: $ProjectRoot" -ForegroundColor Yellow
Write-Host ""

# Option 1: Add to User PATH (Optional)
Write-Host "OPTION 1: Add to User PATH (Optional)" -ForegroundColor Green
Write-Host "Note: PATH change may require terminal restart." -ForegroundColor Gray
Write-Host ""

$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

if ($currentPath -like "*$ProjectRoot*") {
    Write-Host "Directory already in PATH." -ForegroundColor Green
} else {
    Write-Host "Do you want to add $ProjectRoot to your PATH? (Y/N): " -ForegroundColor Yellow -NoNewline
    $response = Read-Host

    if ($response -eq 'Y' -or $response -eq 'y') {
        try {
            $newPath = $currentPath + ";" + $ProjectRoot
            [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
            Write-Host "Added to PATH successfully." -ForegroundColor Green
            Write-Host "Please restart your terminal for changes to take effect." -ForegroundColor Yellow
        } catch {
            Write-Host "Error adding to PATH: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipped adding to PATH." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "OPTION 2: Create PowerShell Function (Session Only)" -ForegroundColor Green
Write-Host "Works immediately in current terminal session." -ForegroundColor Gray
Write-Host ""
function byebac {
    param(
        [Parameter(ValueFromRemainingArguments=$true)]
        [string[]]$Arguments
    )
    & python "$ProjectRoot\byebac.py" @Arguments
}
Write-Host "Session function loaded: byebac" -ForegroundColor Green
Write-Host "Try now: byebac /help" -ForegroundColor White
Write-Host ""

Write-Host "OPTION 3: Add to PowerShell Profile (Permanent)" -ForegroundColor Green
Write-Host "Do you want to add byebac function to your PowerShell profile? (Y/N): " -ForegroundColor Yellow -NoNewline
$response = Read-Host

if ($response -eq 'Y' -or $response -eq 'y') {
    $profilePath = $PROFILE
    $fnBlock = @"
function byebac {
    param(
        [Parameter(ValueFromRemainingArguments=`$true)]
        [string[]]`$Arguments
    )
    & python '$ProjectRoot\byebac.py' @Arguments
}
"@

    # Create profile if it doesn't exist
    if (-not (Test-Path $profilePath)) {
        New-Item -Path $profilePath -ItemType File -Force | Out-Null
        Write-Host "Created PowerShell profile: $profilePath" -ForegroundColor Green
    }

    # Check if byebac function already exists
    $profileContent = Get-Content $profilePath -ErrorAction SilentlyContinue
    if ($profileContent -like "*function byebac*") {
        Write-Host "Function already exists in profile." -ForegroundColor Green
    } else {
        Add-Content -Path $profilePath -Value "`n# BYE BAC CLI Function"
        Add-Content -Path $profilePath -Value $fnBlock
        Write-Host "Added function to PowerShell profile." -ForegroundColor Green
        Write-Host "Profile location: $profilePath" -ForegroundColor Gray
        Write-Host "Run: . `$PROFILE to reload (or restart PowerShell)." -ForegroundColor Yellow
    }
} else {
    Write-Host "Skipped profile setup." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host ""
Write-Host "Quick test:" -ForegroundColor Cyan
Write-Host "1) Run now in this session: byebac /help" -ForegroundColor White
Write-Host "2) If new terminal: run . `$PROFILE then byebac /help" -ForegroundColor White
Write-Host "3) Fallback always works: python $ProjectRoot\byebac.py /help" -ForegroundColor White
Write-Host ""
