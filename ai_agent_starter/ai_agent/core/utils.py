import json, re, yaml, os
from typing import Dict, Any, List
import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"

def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def normalize_path(path: str) -> str:
    return re.sub(r"//+", "/", path.strip())

def extract_paths_from_openapi(spec: Dict[str, Any]) -> List[dict]:
    paths = []
    for p, methods in spec.get("paths", {}).items():
        for m, meta in methods.items():
            paths.append({"method": m.upper(), "path": normalize_path(p)})
    return paths

def has_id_param(path: str) -> bool:
    """Detect whether any placeholder looks ID-like.
    Consider any {...} whose name contains 'id' (e.g., id, user_id, change_request_id, id_change_request).
    """
    names = re.findall(r"\{([^}/]+)\}", path or "")
    for name in names:
        if "id" in str(name).lower():
            return True
    return False

def load_policy(config_dir: str) -> dict:
    """Load policy from YAML or JSON; prefer YAML if both exist."""
    ypath = os.path.join(config_dir, "policy.yaml")
    jpath = os.path.join(config_dir, "policy.json")
    if os.path.exists(ypath):
        return load_yaml(ypath)
    if os.path.exists(jpath):
        return load_json(jpath)
    raise FileNotFoundError(f"No policy file found in {config_dir} (policy.yaml or policy.json)")

def load_rbac_matrix():
    """Load flattened RBAC matrix untuk LLM"""
    return pd.read_csv(DATA_DIR / "rbac_matrix.csv")

def load_roles():
    """Load master roles"""
    return pd.read_csv(DATA_DIR / "roles.csv")

def load_permissions():
    """Load master permissions"""
    return pd.read_csv(DATA_DIR / "permissions.csv")

def get_role_permissions(role_name: str) -> list:
    """Get list permission codes untuk role tertentu"""
    df = load_rbac_matrix()
    perms = df[df['role_name'] == role_name]['permission_code'].tolist()
    return perms

def get_all_roles() -> list:
    """Get list semua role names"""
    return load_roles()['role_name'].tolist()
