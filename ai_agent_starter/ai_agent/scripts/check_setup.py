"""scripts/check_setup.py
Sanity checks for local setup. Resolves project paths relative to this file
so it works regardless of the current working directory.
"""
import os
import sys
import requests
from pathlib import Path
from dotenv import load_dotenv


def _repo_root() -> Path:
    # .../ai_agent_starter/ai_agent/scripts/check_setup.py -> parents[2] = repo root
    return Path(__file__).resolve().parents[2]


def _pkg_root() -> Path:
    # .../ai_agent_starter/ai_agent
    return Path(__file__).resolve().parents[1]


def check_all():
    print("[INFO] Checking local setup...\n")

    issues = []

    # Load .env from multiple possible locations (best practice)
    env_loaded = False
    env_locations = [
        _repo_root() / ".env",                    # ai_agent_starter/.env
        _repo_root().parent / ".env",              # parent directory
        Path.cwd() / ".env",                       # current working directory
        Path(__file__).resolve().parents[3] / ".env"  # potential outer repo root
    ]
    
    for env_path in env_locations:
        if env_path.exists():
            try:
                load_dotenv(dotenv_path=env_path, override=True)
                env_loaded = True
                print(f"[OK ] Loaded .env from: {env_path}")
                break
            except Exception as e:
                pass
    
    if not env_loaded:
        print(f"[INFO] No .env file found. Checked locations:")
        for loc in env_locations[:2]:  # Show first 2 locations
            print(f"      - {loc}")

    cfg_dir = _pkg_root() / "config"
    data_dir = _pkg_root() / "data"

    # Check 1: Files exist
    required_files = [
        cfg_dir / "agent.yaml",
        cfg_dir / "auth.yaml",
        cfg_dir / "policy.yaml",
        data_dir / "roles.csv",
        data_dir / "permissions.csv",
    ]
    # Accept either plural or singular file naming
    role_perm_candidates = [
        data_dir / "role_permissions.csv",
        data_dir / "role_permission.csv",
    ]
    if not any(p.exists() for p in role_perm_candidates):
        issues.append("[ERR] Missing: role_permissions.csv or role_permission.csv in ai_agent/data")
    else:
        print("[OK ] role_permissions mapping found")

    for file in required_files:
        if not Path(file).exists():
            issues.append(f"[ERR] Missing: {file}")
        else:
            print(f"[OK ] {file}")

    # Check 2: Env vars and config base_url
    # API_BASE_URL influences scripts like run_agent; orchestrator uses config/agent.yaml
    env_base = os.getenv("API_BASE_URL")
    if env_base:
        print(f"[OK ] API_BASE_URL (env) = {env_base}")
    else:
        # If config base_url exists, treat missing env as a warning
        issues.append("[WARN] Missing env var: API_BASE_URL (agent.yaml base_url will be used by orchestrator)")
    # Load base_url from agent.yaml
    cfg_base = None
    try:
        import yaml
        cfg = yaml.safe_load((cfg_dir / "agent.yaml").read_text(encoding="utf-8"))
        cfg_base = (cfg or {}).get("base_url")
        if cfg_base:
            print(f"[OK ] base_url (agent.yaml) = {cfg_base}")
    except Exception:
        pass
    if env_base and cfg_base and env_base.rstrip('/') != cfg_base.rstrip('/'):
        print("[WARN] API_BASE_URL (env) differs from agent.yaml base_url. Align these to avoid confusion.")

    llm_provider = (os.getenv("LLM_PROVIDER") or "").strip().lower()
    openai_key = os.getenv("OPENAI_API_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY")
    if llm_provider in ("", "openai") and openai_key:
        print("[OK ] LLM configured: OpenAI")
    elif llm_provider == "gemini" and gemini_key:
        print("[OK ] LLM configured: Gemini")
    else:
        print("[WARN] LLM not configured (or missing key). Agent will run in deterministic mode.")

    # Check 3: API reachable (try env, then config), unless dry_run enabled
    # Detect dry_run from agent.yaml
    dry_run = False
    try:
        import yaml
        cfg = yaml.safe_load((cfg_dir / "agent.yaml").read_text(encoding="utf-8"))
        dry_run = bool((cfg or {}).get("dry_run", False))
    except Exception:
        pass

    def _check_api(url: str) -> bool:
        try:
            requests.get(f"{url.rstrip('/')}/health", timeout=5)
            print(f"[OK ] API reachable at {url}")
            return True
        except Exception:
            issues.append(f"[ERR] Cannot reach API at {url}")
            return False

    if dry_run:
        print("[OK ] dry_run enabled in agent.yaml: skipping API reachability check")
    else:
        any_ok = False
        if env_base:
            any_ok = _check_api(env_base) or any_ok
        if cfg_base and (not env_base or cfg_base.rstrip('/') != env_base.rstrip('/')):
            any_ok = _check_api(cfg_base) or any_ok

    # Summary
    print("\n" + "=" * 50)
    if issues:
        print("[WARN] Issues found:")
        for issue in issues:
            print(f"  {issue}")
        sys.exit(1)
    else:
        print("[OK ] All checks passed! Ready to run.")


if __name__ == "__main__":
    check_all()
