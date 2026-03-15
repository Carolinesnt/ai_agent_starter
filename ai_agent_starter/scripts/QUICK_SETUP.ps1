# Quick Setup for BYE BAC CLI
# Just run this in PowerShell: . .\scripts\QUICK_SETUP.ps1
# Purpose: load current shell with byebac function + .env variables (session-only).
# Main command after load: byebac /help

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

# Load .env file if exists
$EnvFile = Join-Path $ProjectRoot ".env"
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]*)\s*=\s*(.*)$') {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            # Remove quotes if present
            $value = $value -replace '^["'']|["'']$', ''
            [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
    Write-Host "Environment variables loaded from .env" -ForegroundColor Green
}

function byebac {
    param(
        [Parameter(ValueFromRemainingArguments=$true)]
        [string[]]$Arguments
    )
    & python "$ProjectRoot\byebac.py" @Arguments
}

Write-Host "BYE BAC CLI loaded." -ForegroundColor Green
Write-Host "You can now use: byebac /help" -ForegroundColor Cyan
Write-Host ""
Write-Host "To make this permanent, run: .\scripts\SETUP_CLI.ps1" -ForegroundColor Yellow
Write-Host ""
