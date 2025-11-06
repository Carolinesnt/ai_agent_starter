#!/usr/bin/env bash
# BYE BAC CLI Launcher for Unix/Linux/Mac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/byebac.py" "$@"
