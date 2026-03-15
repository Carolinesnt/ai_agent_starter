@echo off
REM BYE BAC CLI Launcher for Windows (cmd)
REM Purpose: forward all arguments to byebac.py from this folder.
REM Usage: byebac /help  |  byebac /runagent
python -u "%~dp0byebac.py" %*
