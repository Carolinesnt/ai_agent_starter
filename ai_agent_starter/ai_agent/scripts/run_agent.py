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

# ✅ Load environment
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
    import requests
    base_url = os.getenv('API_BASE_URL', 'http://localhost:8080')
    
    try:
        resp = requests.get(f"{base_url}/health", timeout=5)
        console.print(f"✅ API server running at {base_url}", style="green")
        return True
    except requests.exceptions.ConnectionError:
        console.print(f"❌ API server not running at {base_url}", style="red")
        console.print("💡 Start your API server first:", style="yellow")
        console.print("   cd your-api-project && npm run dev", style="dim")
        return False
    except Exception as e:
        console.print(f"⚠️  Warning: {e}", style="yellow")
        return False

def main():
    render_banner()
    
    # ✅ Pre-flight checks
    if not check_api_server():
        sys.exit(1)
    
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
            console.print("✅ LLM provider: OpenAI", style="green")
    elif llm_provider == 'gemini':
        provider_name = 'gemini'
        if not gemini_key:
            console.print("⚠️ LLM provider is Gemini, but GEMINI_API_KEY is missing. Running in deterministic mode.", style="yellow")
            llm_provider = ''
        else:
            console.print("✅ LLM provider: Gemini", style="green")
    else:
        console.print(f"⚠️ Unknown LLM provider '{llm_provider}'. Running in deterministic mode.", style="yellow")
    
    console.print("\n🚀 Starting agent...\n")
    
    try:
        # ✅ Run orchestrator
        agent = AgentOrchestrator()
        results = agent.run()
        
        # ✅ Print summary
        console.print("\n✅ Testing completed!", style="green bold")
        console.print(f"📊 Total tests: {results['total_tests']}")
        console.print(f"🔴 Vulnerabilities found: {results['vulnerabilities']}", 
                     style="red" if results['vulnerabilities'] > 0 else "green")
        console.print(f"📁 Report saved to: {results['report_path']}")
        
    except KeyboardInterrupt:
        console.print("\n⚠️  Agent stopped by user", style="yellow")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n❌ Error: {e}", style="red")
        console.print("\n[dim]Check logs at: ai_agent/runs/logs/agent.log[/dim]")
        sys.exit(1)

if __name__ == "__main__":
    main()