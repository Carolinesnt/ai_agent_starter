from typing import List, Dict, Any, Tuple
from collections import Counter
from .memory import TestCase, Result
import os
from pathlib import Path


def _locate_rules_file() -> Path | None:
    # Priority: ENV override, then common locations upward from CWD
    env = os.getenv("RULES_FILE") or os.getenv("RULE_FILE")
    if env:
        p = Path(env)
        if p.exists():
            return p
    # Try repo root (cwd), then parent dirs, then ai_agent_starter/rule.txt
    cand_names = ["rule.txt", "rules.txt"]
    start = Path.cwd()
    for up in [start] + list(start.parents)[:3]:
        for name in cand_names:
            p = up / name
            if p.exists():
                return p
    # Specific common path for this repo layout
    p = Path("ai_agent_starter") / "rule.txt"
    return p if p.exists() else None


def _parse_rule_line(line: str, out: Dict[str, set]):
    import re
    ls = line.lower()
    nums = set(int(n) for n in re.findall(r"\b(\d{3})\b", ls))
    if not nums:
        # Keywords without explicit code
        if "conflict" in ls:
            out["non_finding"].add(409)
        if "not found" in ls:
            out["not_found"].add(404)
        return
    if "not found" in ls:
        out["not_found"].update(nums)
    elif "bukan temuan" in ls or "not a finding" in ls or "non finding" in ls:
        out["non_finding"].update(nums)
    elif "error" in ls and any(n >= 500 for n in nums):
        out["error_like"].update({n for n in nums if n >= 500})


def _load_status_rules() -> Dict[str, set]:
    # Defaults aligned with best-practice and project rules
    rules = {
        "non_finding": set([400, 409, 422]),  # validation/conflict/unprocessable
        "not_found": set([404]),         # not found is not a BAC finding
        "error_like": set(),            # 5xx handled separately
    }
    try:
        rf = _locate_rules_file()
        if rf and rf.exists():
            for line in rf.read_text(encoding="utf-8").splitlines():
                _parse_rule_line(line, rules)
    except Exception:
        pass
    return rules


_STATUS_RULES = _load_status_rules()

def _policy_allowed_endpoints(policy, role: str):
    rules = policy.get("rbac_rules", {})
    role_rules = rules.get(role) or rules.get(str(role)) or {}
    allowed = set(role_rules.get("allowed_endpoints", []) or [])
    critical_deny = set(role_rules.get("critical_deny", []) or [])
    return allowed, critical_deny

def expected_status(policy, tc: TestCase) -> Dict[str, Any]:
    # Format A: explicit rules with allow/deny and self semantics
    for rule in policy.get("rules", []):
        if rule.get("method","").upper() == tc.method.upper() and rule.get("path") == tc.path:
            # Interpret self semantics:
            # - self: true  -> only own resources
            # - self: false -> other users' resources
            # - self: "any" -> both own and others' resources
            exp = False
            for a in rule.get("allow", []):
                if a.get("role") != tc.role:
                    continue
                sval = a.get("self")
                if sval == "any":
                    exp = True
                    break
                if tc.self_access and (sval is True):
                    exp = True
                    break
                if (not tc.self_access) and (sval is False):
                    exp = True
                    break
            # Deny may surface as 401/403 or 404 (not-found for other user's resource)
            return {"status_in":[200], "status_not_in":[401,403,404]} if exp else {"status_in":[401,403,404], "status_not_in":[200]}
    # Format B: rbac_rules with allowed_endpoints per-role (assume self allowed, other denied)
    if "rbac_rules" in policy:
        key = f"{tc.method.upper()}:{tc.path}"
        allowed, critical_deny = _policy_allowed_endpoints(policy, tc.role)
        if key in critical_deny:
            return {"status_in":[401,403,404], "status_not_in":[200]}
        if key in allowed:
            if tc.self_access:
                return {"status_in":[200], "status_not_in":[401,403]}
            else:
                # other users' resource: deny acceptable via 401/403/404
                return {"status_in":[401,403,404], "status_not_in":[200]}
    # default: unknown
    return {"status_in":[200,401,403], "status_not_in":[]}

def classify(exp: Dict[str, Any], actual_status: int) -> str:
    # 5xx -> system stability/error, do not treat as BAC finding
    if 500 <= int(actual_status) <= 599:
        return "ERROR"
    # 0 -> skipped (e.g., protected delete not executed)
    if int(actual_status) == 0:
        return "SKIP"
    # Best-practice: 404 is not a BAC finding; mark separately (from rules file)
    if int(actual_status) in _STATUS_RULES.get("not_found", set([404])):
        return "NOT_FOUND"
    # Local/project rules: treat certain 4xx as non-BAC finding (validation/conflict)
    if int(actual_status) in _STATUS_RULES.get("non_finding", set([400,409])):
        return "TN"
    if actual_status in exp.get("status_in", []):
        # Benar sesuai ekspektasi
        if actual_status in [401,403]:
            return "TN"  # ditolak sesuai harapan (tidak ada celah)
        else:
            return "TP_ALLOW"  # diizinkan sesuai harapan (untuk kasus self/role sah)
    else:
        # Tidak sesuai ekspektasi
        if actual_status == 200:
            return "FN"  # seharusnya ditolak tapi lolos -> celah
        else:
            return "FP"  # seharusnya diizinkan tapi ditolak

def confusion_counts(results: List[Result], policy) -> Dict[str, int]:
    c = Counter()
    for r in results:
        exp = expected_status(policy, r.tc)
        lab = classify(exp, r.status_code)
        c[lab] += 1
    # Map TP_ALLOW to TP: allowed endpoints returning 200 are True Positives
    return {
        "TP": c.get("TP",0) + c.get("TP_ALLOW",0),
        "FP": c.get("FP",0),
        "FN": c.get("FN",0),
        "TN": c.get("TN",0),
        "ERR": c.get("ERROR",0),
        "NF": c.get("NOT_FOUND",0),
    }

def metrics(cf: Dict[str, int]) -> Dict[str, float]:
    TP, FP, FN, TN = cf["TP"], cf["FP"], cf["FN"], cf["TN"]
    precision = TP / (TP + FP) if (TP+FP)>0 else 0.0
    recall = TP / (TP + FN) if (TP+FN)>0 else 0.0
    f1 = 2*precision*recall/(precision+recall) if (precision+recall)>0 else 0.0
    acc = (TP+TN)/max(1,(TP+TN+FP+FN))
    return {"precision": round(precision,3), "recall": round(recall,3), "f1": round(f1,3), "accuracy": round(acc,3)}

def coverage(tests: List[TestCase], roles: List[str], endpoints: List[Dict[str,Any]]) -> Dict[str, Any]:
    total_pairs = len(roles) * len(endpoints)
    tested_pairs = len({(t.role, t.method, t.path) for t in tests})
    pct = int(round((tested_pairs/max(1,total_pairs))*100))
    return {"endpoints": len(endpoints), "roles": len(roles), "total_pairs": total_pairs,
            "tested_pairs": tested_pairs, "coverage_pct": pct}

def time_to_detect(results: List[Result], policy, start_ts: float) -> Dict[str, Any]:
    """Hitung waktu hingga temuan pertama (FN) sejak start_ts.
    Kembalikan dict dengan seconds (float) atau None, termasuk index test ke berapa (1-based).
    """
    first_ts = None
    first_idx = None
    for idx, r in enumerate(results, start=1):
        exp = expected_status(policy, r.tc)
        lab = classify(exp, r.status_code)
        if lab == "FN":
            first_ts = r.ts or None
            first_idx = idx
            break
    return {
        "seconds": round((first_ts - start_ts), 3) if (first_ts and start_ts) else None,
        "test_index": first_idx,
    }

def bac_type(policy: dict, tc: TestCase) -> str:
    """
    Determine BAC type based on test case and policy context.
    
    Returns:
        - 'horizontal': IDOR - same privilege level, accessing other user's resources
        - 'vertical': BOLA - privilege escalation attempt
        - 'baseline': Normal expected operations (self access)
        - 'auth': Authentication related tests
    """
    # Check mutation for explicit type hints
    mut = tc.mutation or {}
    mut_type = str(mut.get("type", "")).upper()
    
    # Vertical escalation (privilege escalation)
    if mut_type in ("BOLA", "VERTICAL", "ESCALATION"):
        return 'vertical'
    
    # Check if accessing with different role than original
    if mut.get("as_role") and mut.get("as_role") != tc.role:
        return 'vertical'
    
    # Horizontal access (IDOR - other user's resource at same level)
    if mut_type == "IDOR" or mut.get("variant") == "other":
        return 'horizontal'
    
    # Self access = false indicates testing access to other users' resources
    if not tc.self_access:
        return 'horizontal'
    
    # Check for no-auth attempts (treat as vertical since it's trying to bypass auth)
    if mut.get("no_auth") or mut.get("without_auth") or mut_type in ("NO_AUTH", "NEGATIVE_AUTH"):
        return 'vertical'
    
    # Authentication endpoints (login, logout, register, etc.)
    path_lower = tc.path.lower()
    if any(keyword in path_lower for keyword in ['/auth/', '/login', '/logout', '/register', '/signin', '/signup']):
        return 'auth'
    
    # Default baseline (self access, normal operations)
    return 'baseline'
