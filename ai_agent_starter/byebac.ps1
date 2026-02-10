# BYE BAC CLI Launcher for PowerShell
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& python "$ScriptDir\byebac.py" $args
