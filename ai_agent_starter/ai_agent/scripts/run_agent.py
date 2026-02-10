#!/usr/bin/env python3
"""
Run AI Security Testing Agent - Local Development Mode
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

# ✅ Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Robust .env loading (search repo root), fallback to .env.example if .env not found
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

from ai_agent.core.orchestrator import AgentOrchestrator

console = Console()

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
        console.print(f"\n❌ Error: {e}", style="red")
        console.print("\n[dim]Check logs at: ai_agent/runs/logs/agent.log[/dim]")
        sys.exit(1)

if __name__ == "__main__":
    main()
