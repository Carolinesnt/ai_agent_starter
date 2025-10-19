# scripts/check_setup.py
import os
import sys
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

def check_all():
    print("🔍 Checking local setup...\n")
    
    issues = []
    
    # Check 1: Files exist
    required_files = [
        'ai_agent/config/agent.yaml',
        'ai_agent/config/auth.yaml',
        'ai_agent/config/policy.yaml',
        'ai_agent/data/roles.csv',
        'ai_agent/data/permissions.csv',
    ]
    # Accept either plural or singular file naming
    role_perm_candidates = [
        'ai_agent/data/role_permissions.csv',
        'ai_agent/data/role_permission.csv',
    ]
    if not any(Path(p).exists() for p in role_perm_candidates):
        issues.append("\u2757\ufe0f Missing: role_permissions.csv or role_permission.csv in ai_agent/data")
    else:
        print("\u2705 role_permissions mapping found")
    
    for file in required_files:
        if not Path(file).exists():
            issues.append(f"❌ Missing: {file}")
        else:
            print(f"✅ {file}")
    
    # Check 2: Env vars
    # API_BASE_URL is required; LLM keys are optional (OpenAI or Gemini)
    if not os.getenv('API_BASE_URL'):
        issues.append("❌ Missing env var: API_BASE_URL")
    else:
        print(f"✅ API_BASE_URL = {os.getenv('API_BASE_URL')}")

    llm_provider = (os.getenv('LLM_PROVIDER') or '').strip().lower()
    openai_key = os.getenv('OPENAI_API_KEY')
    gemini_key = os.getenv('GEMINI_API_KEY')
    if llm_provider in ('', 'openai') and openai_key:
        print("✅ LLM configured: OpenAI")
    elif llm_provider == 'gemini' and gemini_key:
        print("✅ LLM configured: Gemini")
    else:
        print("⚠️ LLM not configured (or missing key). Agent will run in deterministic mode.")
    
    # Check 3: API reachable
    base_url = os.getenv('API_BASE_URL')
    try:
        resp = requests.get(f"{base_url}/health", timeout=5)
        print(f"✅ API reachable at {base_url}")
    except:
        issues.append(f"❌ Cannot reach API at {base_url}")
    
    # Summary
    print("\n" + "="*50)
    if issues:
        print("⚠️  Issues found:")
        for issue in issues:
            print(f"  {issue}")
        sys.exit(1)
    else:
        print("✅ All checks passed! Ready to run.")

if __name__ == "__main__":
    check_all()
