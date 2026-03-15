# Setup virtual environment for AI Agent Starter (PowerShell)
# Purpose: create/recreate virtual environment and install requirements.
# Usage: .\scripts\setup_venv.ps1
# Next step: .\scripts\activate_venv.ps1 then python byebac.py /check

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Push-Location $ProjectRoot
try {
    Write-Host "=== Setup Virtual Environment ===" -ForegroundColor Cyan
    Write-Host ""

    $venvDir = if (Test-Path ".venv") { ".venv" } else { "venv" }
    $activateScript = Join-Path $venvDir "Scripts\Activate.ps1"

    if ((Test-Path "venv") -or (Test-Path ".venv")) {
        Write-Host "Virtual environment already exists." -ForegroundColor Yellow
        $response = Read-Host "Delete and recreate? (y/N)"
        if ($response -in @("y", "Y")) {
            if (Test-Path "venv") { Remove-Item -Recurse -Force "venv" }
            if (Test-Path ".venv") { Remove-Item -Recurse -Force ".venv" }
            $venvDir = ".venv"
            $activateScript = Join-Path $venvDir "Scripts\Activate.ps1"
            Write-Host "Old virtual environment deleted." -ForegroundColor Green
        } else {
            Write-Host "Using existing virtual environment." -ForegroundColor Green
            Write-Host "Activate with: .\$activateScript" -ForegroundColor White
            exit 0
        }
    }

    Write-Host "Creating virtual environment..." -ForegroundColor Cyan
    python -m venv $venvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to create virtual environment." -ForegroundColor Red
        Write-Host "Make sure Python is installed and available in PATH." -ForegroundColor Yellow
        exit 1
    }

    Write-Host "Activating virtual environment..." -ForegroundColor Cyan
    . ".\$activateScript"

    Write-Host "Upgrading pip..." -ForegroundColor Cyan
    python -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to upgrade pip." -ForegroundColor Red
        exit 1
    }

    Write-Host "Installing dependencies from requirements.txt..." -ForegroundColor Cyan
    python -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to install dependencies." -ForegroundColor Red
        exit 1
    }

    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host "Setup complete." -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host ""
    Write-Host "Virtual environment is active and dependencies are installed." -ForegroundColor Cyan
    Write-Host "Run agent with: python byebac.py /runagent" -ForegroundColor White
    Write-Host "Deactivate with: deactivate" -ForegroundColor White
} finally {
    Pop-Location
}
