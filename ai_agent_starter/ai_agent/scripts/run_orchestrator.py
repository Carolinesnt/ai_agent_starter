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

# Load environment variables from .env (search repo root first), fallback to .env.example if .env not found
try:
    repo_root = Path(__file__).resolve().parents[2]
    candidates = [
        repo_root / "ai_agent_starter" / ".env",
        repo_root / ".env",
        repo_root.parent / ".env",
        Path.cwd() / ".env",
    ]
    loaded = False
    for env_path in candidates:
        if env_path.exists():
            load_dotenv(dotenv_path=env_path, override=True)
            loaded = True
            break
    if not loaded:
        # try .env.example as fallback template
        examples = [
            repo_root / "ai_agent_starter" / ".env.example",
            repo_root / ".env.example",
            Path.cwd() / ".env.example",
        ]
        for env_path in examples:
            if env_path.exists():
                load_dotenv(dotenv_path=env_path, override=True)
                loaded = True
                break
    if not loaded:
        load_dotenv()  # final fallback to current dir
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
