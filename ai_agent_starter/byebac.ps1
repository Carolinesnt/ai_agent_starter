# BYE BAC CLI Launcher for PowerShell
# Purpose: forward all arguments to byebac.py from this folder.
# Usage: .\byebac.ps1 /help   or   byebac /status (if PATH/function already set)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& python -u "$ScriptDir\byebac.py" $args
