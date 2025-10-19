#!/usr/bin/env python3
"""
Minimal runner to execute the BAC testing orchestrator without extra checks.
Uses only requests/pyyaml stack and agent configs.
"""
import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure repository root on sys.path to import package `ai_agent`
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Load environment variables from .env if present
try:
    load_dotenv()
except Exception:
    pass

from ai_agent.core.orchestrator import AgentOrchestrator

if __name__ == "__main__":
    # Resolve absolute paths so it works regardless of CWD
    pkg_root = Path(__file__).resolve().parents[1]  # ai_agent directory
    config_dir = str(pkg_root / "config")
    data_dir = str(pkg_root / "data")
    runs_dir = str(pkg_root / "runs")
    agent = AgentOrchestrator(config_dir=config_dir, data_dir=data_dir, runs_dir=runs_dir)
    out = agent.run()
    print(out.get("report_path"))
