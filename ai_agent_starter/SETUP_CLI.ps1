# BYE BAC CLI Setup Script for Windows PowerShell
# This script adds byebac to your PATH so you can run it from anywhere

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BatFile = Join-Path $ScriptDir "byebac.bat"
$Ps1File = Join-Path $ScriptDir "byebac.ps1"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                  BYE BAC CLI Setup                           ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if files exist
if (-not (Test-Path $BatFile)) {
    Write-Host "❌ Error: byebac.bat not found!" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $Ps1File)) {
    Write-Host "❌ Error: byebac.ps1 not found!" -ForegroundColor Red
    exit 1
}

Write-Host "📁 Installation Directory: $ScriptDir" -ForegroundColor Yellow
Write-Host ""

# Option 1: Add to User PATH (Recommended)
Write-Host "🔧 OPTION 1: Add to User PATH (Recommended)" -ForegroundColor Green
Write-Host "   After this, you can run: byebac /help from any directory" -ForegroundColor Gray
Write-Host ""

$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

if ($currentPath -like "*$ScriptDir*") {
    Write-Host "✅ Directory already in PATH!" -ForegroundColor Green
} else {
    Write-Host "   Do you want to add $ScriptDir to your PATH? (Y/N): " -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    
    if ($response -eq 'Y' -or $response -eq 'y') {
        try {
            $newPath = $currentPath + ";" + $ScriptDir
            [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
            Write-Host "✅ Added to PATH successfully!" -ForegroundColor Green
            Write-Host "⚠️  Please restart your terminal for changes to take effect." -ForegroundColor Yellow
        } catch {
            Write-Host "❌ Error adding to PATH: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "⏭️  Skipped adding to PATH" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "🔧 OPTION 2: Create PowerShell Alias (Session Only)" -ForegroundColor Green
Write-Host "   Quick setup for current session only" -ForegroundColor Gray
Write-Host ""
Write-Host "   Run this command in your PowerShell:" -ForegroundColor Cyan
Write-Host "   Set-Alias byebac '$Ps1File'" -ForegroundColor White
Write-Host ""

Write-Host "🔧 OPTION 3: Add to PowerShell Profile (Permanent Alias)" -ForegroundColor Green
Write-Host "   Do you want to add byebac alias to your PowerShell profile? (Y/N): " -ForegroundColor Yellow -NoNewline
$response = Read-Host

if ($response -eq 'Y' -or $response -eq 'y') {
    $profilePath = $PROFILE
    $aliasLine = "Set-Alias byebac '$Ps1File'"
    
    # Create profile if it doesn't exist
    if (-not (Test-Path $profilePath)) {
        New-Item -Path $profilePath -ItemType File -Force | Out-Null
        Write-Host "✅ Created PowerShell profile: $profilePath" -ForegroundColor Green
    }
    
    # Check if alias already exists
    $profileContent = Get-Content $profilePath -ErrorAction SilentlyContinue
    if ($profileContent -like "*byebac*") {
        Write-Host "✅ Alias already exists in profile!" -ForegroundColor Green
    } else {
        Add-Content -Path $profilePath -Value "`n# BYE BAC CLI Alias"
        Add-Content -Path $profilePath -Value $aliasLine
        Write-Host "✅ Added alias to PowerShell profile!" -ForegroundColor Green
        Write-Host "   Profile location: $profilePath" -ForegroundColor Gray
        Write-Host "⚠️  Run: . `$PROFILE  to reload (or restart PowerShell)" -ForegroundColor Yellow
    }
} else {
    Write-Host "⏭️  Skipped profile setup" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "✅ Setup Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📖 Quick Test:" -ForegroundColor Cyan
Write-Host "   If you added to PATH, restart terminal then run: byebac /help" -ForegroundColor White
Write-Host "   Otherwise run: python $ScriptDir\byebac.py /help" -ForegroundColor White
Write-Host ""
