#!/usr/bin/env python3
"""
Convert policy between YAML and JSON in ai_agent/config.

Usage examples:
  python ai_agent/scripts/convert_policy.py --to json
  python ai_agent/scripts/convert_policy.py --to yaml

If neither policy.yaml nor policy.json exists, exits with error.
"""
import argparse
import json
import os
from pathlib import Path

import yaml

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"

def load_policy_any():
    y = CONFIG_DIR / "policy.yaml"
    j = CONFIG_DIR / "policy.json"
    if y.exists():
        return yaml.safe_load(y.read_text(encoding="utf-8")), "yaml"
    if j.exists():
        return json.loads(j.read_text(encoding="utf-8")), "json"
    raise SystemExit(f"No policy file found in {CONFIG_DIR} (policy.yaml or policy.json)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", choices=["json","yaml"], required=True, help="Target format")
    args = ap.parse_args()
    data, fmt = load_policy_any()
    if args.to == "json":
        out = CONFIG_DIR / "policy.json"
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Wrote {out}")
    else:
        out = CONFIG_DIR / "policy.yaml"
        out.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
        print(f"Wrote {out}")

if __name__ == "__main__":
    main()

