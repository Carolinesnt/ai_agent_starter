#!/usr/bin/env bash
# BYE BAC CLI Launcher for Unix/Linux/Mac
# Purpose: forward all arguments to byebac.py from this folder.
# Usage: ./byebac.sh /help   or   ./byebac.sh /runagent

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 -u "$SCRIPT_DIR/byebac.py" "$@"
