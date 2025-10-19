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
    console.print(Panel.fit(
        "[bold cyan]AI Security Testing Agent[/bold cyan]\n"
        "[dim]Local Development Mode[/dim]",
        border_style="cyan"
    ))
    
    # ✅ Pre-flight checks
    if not check_api_server():
        sys.exit(1)
    
    # ✅ Check credentials
    if not os.getenv('OPENAI_API_KEY'):
        console.print("❌ OPENAI_API_KEY not found in .env", style="red")
        sys.exit(1)
    
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