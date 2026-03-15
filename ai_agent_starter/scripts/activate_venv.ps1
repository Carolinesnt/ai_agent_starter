# Quick activate virtual environment (PowerShell)
# Purpose: activate existing virtual environment for local development.
# Usage: .\scripts\activate_venv.ps1
# After active: python byebac.py /check

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Push-Location $ProjectRoot
try {
    $activateScript = $null
    if (Test-Path ".\venv\Scripts\Activate.ps1") {
        $activateScript = ".\venv\Scripts\Activate.ps1"
    } elseif (Test-Path ".\.venv\Scripts\Activate.ps1") {
        $activateScript = ".\.venv\Scripts\Activate.ps1"
    }

    if ($activateScript) {
        Write-Host "Activating virtual environment..." -ForegroundColor Cyan
        . $activateScript

        $pythonPath = (Get-Command python).Source
        Write-Host "Virtual environment active." -ForegroundColor Green
        Write-Host ("Python path: " + $pythonPath) -ForegroundColor Cyan
        Write-Host "Run agent with: python byebac.py /runagent" -ForegroundColor White
    } else {
        Write-Host "Virtual environment not found." -ForegroundColor Red
        Write-Host "Create it first with: .\scripts\setup_venv.ps1" -ForegroundColor Yellow
        Write-Host "Or manually: python -m venv .venv" -ForegroundColor Yellow
    }
} finally {
    Pop-Location
}
