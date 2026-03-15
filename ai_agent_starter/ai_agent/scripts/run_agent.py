#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run AI Security Testing Agent - Local Development Mode
"""
import os
import sys
from pathlib import Path
import traceback
from datetime import datetime, timezone

# Fix encoding for Windows console
if sys.platform == 'win32':
    try:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except:
        pass

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None  # python-dotenv not installed; run: pip install python-dotenv
from rich.console import Console
from rich.panel import Panel

# ✅ Add project root to path
# run_agent.py is in ai_agent/scripts/, so parent.parent is ai_agent_starter root
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent.parent  # Go up from scripts/ -> ai_agent/ -> ai_agent_starter/
sys.path.insert(0, str(project_root))

# Robust .env loading (search repo root), fallback to .env.example if .env not found
if load_dotenv is not None:
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
            load_dotenv()
    except Exception:
        load_dotenv()
else:
    print("Warning: python-dotenv not installed. Run: pip install python-dotenv", file=sys.stderr)

from ai_agent.core.orchestrator import AgentOrchestrator

console = Console()

def _write_agent_log(message: str) -> None:
    """Persist runtime errors to ai_agent/runs/logs/agent.log."""
    try:
        log_dir = project_root / "ai_agent" / "runs" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "agent.log"
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
    except Exception:
        # Logging should never break runner behavior
        pass

def render_banner():
    """Render a big ASCII banner and subtitle (configurable via env).
    BANNER_TITLE, BANNER_SUBTITLE, BANNER_FONT can be set in .env
    """
    title = os.getenv("BANNER_TITLE", "AI Security Testing Agent")
    subtitle = os.getenv("BANNER_SUBTITLE", "Broken Access Control (IDOR/BOLA) Orchestrator")
    font = os.getenv("BANNER_FONT", "Slant")
    try:
        from pyfiglet import Figlet
        fig = Figlet(font=font)
        ascii_title = fig.renderText(title)
        console.print(f"[bold cyan]{ascii_title}[/bold cyan]")
    except Exception:
        # Fallback to a simple panel if pyfiglet not available
        console.print(Panel.fit(f"[bold cyan]{title}[/bold cyan]\n[dim]{subtitle}[/dim]", border_style="cyan"))
        return
    # Subtitle panel below the ASCII art
    console.print(Panel.fit(f"[dim]{subtitle}[/dim]", border_style="cyan"))

def check_api_server():
    """Check if local API is running"""
    return True
def main():
    render_banner()
    
    # ✅ Pre-flight checks
    # Health check skipped: no /health endpoint
    
    # ✅ LLM provider check (optional)
    llm_provider = (os.getenv('LLM_PROVIDER') or '').strip().lower()
    openai_key = os.getenv('OPENAI_API_KEY')
    gemini_key = os.getenv('GEMINI_API_KEY')
    provider_name = 'deterministic'
    if llm_provider in ('', 'openai'):
        provider_name = 'openai'
        if not openai_key:
            console.print("⚠️ LLM provider set to OpenAI (or default), but OPENAI_API_KEY is missing. Running in deterministic mode.", style="yellow")
            llm_provider = ''  # force deterministic behavior
        else:
            # Get OpenAI model from env or use default
            openai_model = os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
            console.print(f"✅ LLM provider: OpenAI ({openai_model})", style="green")
    elif llm_provider == 'gemini':
        provider_name = 'gemini'
        if not gemini_key:
            console.print("⚠️ LLM provider is Gemini, but GEMINI_API_KEY is missing. Running in deterministic mode.", style="yellow")
            llm_provider = ''
        else:
            # Get Gemini model from env or use default
            gemini_model = os.getenv('GEMINI_MODEL', 'gemini-1.5-flash')
            console.print(f"✅ LLM provider: Gemini ({gemini_model})", style="green")
    else:
        console.print(f"⚠️ Unknown LLM provider '{llm_provider}'. Running in deterministic mode.", style="yellow")
    
    console.print("\n🚀 Starting agent...\n")
    
    try:
        # ✅ Run orchestrator
        agent = AgentOrchestrator()
        results = agent.run()
        
        # Print summary (clean output)
        console.print("\nTesting completed!", style="green bold")
        total = int(results.get("total_tests", 0) or 0)
        vulns = int(results.get("vulnerabilities", 0) or 0)
        console.print(f"Total tests: {total}")
        console.print(f"Vulnerabilities found: {vulns}", style="red" if vulns > 0 else "green")
        m = results.get("metrics") or {"precision":0.0,"recall":0.0,"f1":0.0,"accuracy":0.0}
        console.print(f"Metrics -> precision: {m.get('precision',0.0)}, recall: {m.get('recall',0.0)}, f1: {m.get('f1',0.0)}, accuracy: {m.get('accuracy',0.0)}")
        console.print(f"Report saved to: {results.get('report_path','')}" )
    except KeyboardInterrupt:
        console.print("\n⚠️  Agent stopped by user", style="yellow")
        sys.exit(0)
    except Exception as e:
        err_text = str(e)
        tb = traceback.format_exc()
        _write_agent_log(f"ERROR: {err_text}\n{tb}")
        console.print(f"\n❌ Error: {err_text}", style="red")
        if "getaddrinfo failed" in err_text.lower():
            console.print("[yellow]Hint: DNS/network ke provider LLM gagal. Cek internet/proxy/firewall atau nonaktifkan strict summary.[/yellow]")
        console.print("\n[dim]Check logs at: ai_agent/runs/logs/agent.log[/dim]")
        sys.exit(1)

if __name__ == "__main__":
    main()
