# Quick Setup for BYE BAC CLI
# Just run this in PowerShell: . .\QUICK_SETUP.ps1

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Load .env file if exists
$EnvFile = Join-Path $ScriptDir ".env"
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
    Write-Host "✅ Environment variables loaded from .env" -ForegroundColor Green
}

function byebac {
    param(
        [Parameter(ValueFromRemainingArguments=$true)]
        [string[]]$Arguments
    )
    
    & python "$ScriptDir\byebac.py" @Arguments
}

Write-Host "✅ BYE BAC CLI loaded!" -ForegroundColor Green
Write-Host "   You can now use: byebac /help" -ForegroundColor Cyan
Write-Host ""
Write-Host "💡 To make this permanent, add to your PowerShell profile:" -ForegroundColor Yellow
Write-Host "   Run: .\SETUP_CLI.ps1" -ForegroundColor White
Write-Host ""
