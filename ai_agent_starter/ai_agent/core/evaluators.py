from typing import List, Dict, Any, Tuple
from collections import Counter
from .memory import TestCase, Result
from .utils import has_id_param, normalize_path
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


def _success_statuses_for_method(method: str) -> List[int]:
    """Return acceptable success HTTP status codes for a given method.
    Keeps semantics simple and safe without parsing OpenAPI responses.
    """
    m = (method or "").strip().upper()
    mapping = {
        "GET": [200],
        "HEAD": [200],
        "OPTIONS": [200],
        "POST": [200, 201, 202],
        "PUT": [200, 204],
        "PATCH": [200, 204],
        "DELETE": [200, 204],
    }
    # Fallback: treat common 2xx as success
    return mapping.get(m, [200, 201, 202, 204])

def _policy_allowed_endpoints(policy, role: str):
    rules = policy.get("rbac_rules", {})
    role_rules = rules.get(role) or rules.get(str(role)) or {}
    allowed = set(role_rules.get("allowed_endpoints", []) or [])
    denied = set(role_rules.get("denied_endpoints", []) or [])
    critical_deny = set(role_rules.get("critical_deny", []) or [])
    self_only = set(role_rules.get("self_only_endpoints", []) or [])
    return allowed, denied, critical_deny, self_only

def _match_endpoint_pattern(method: str, path: str, pattern: str) -> bool:
    """Return True if METHOD:path matches METHOD:/path with placeholders in pattern.
    Pattern examples: "GET:/user/{user_id}", "POST:/role/{id_role}/permissions"
    """
    try:
        if not isinstance(pattern, str) or ':' not in pattern:
            return False
        pm, pp = pattern.split(':', 1)
        if str(pm).strip().upper() != str(method).strip().upper():
            return False
        p = normalize_path(pp)
        # Escape regex special chars except placeholder braces
        import re
        # Replace placeholders {...} with segment matcher (no slash)
        rx = re.sub(r"\{[^}]+\}", r"[^/]+", re.escape(p).replace(r"\{", "{").replace(r"\}", "}"))
        # Ensure full path match
        return re.fullmatch(rx, normalize_path(path)) is not None
    except Exception:
        return False

def _in_endpoints(method: str, path: str, patterns: set) -> bool:
    for pat in list(patterns or []):
        try:
            if _match_endpoint_pattern(method, path, pat):
                return True
        except Exception:
            continue
    return False


def roles_allowed_for_endpoint(policy: Dict[str, Any], method: str, path: str) -> List[str]:
    """
    Return role names for which (method, path) is allowed by policy.
    Used for critical_endpoints.csv allowed_roles so CSV reflects policy (existing condition).
    """
    path_norm = normalize_path(path or "")
    rules = (policy or {}).get("rbac_rules", {}) or {}
    # /auth/me/ is allowed for any authenticated role (current user profile)
    if path_norm in ("/auth/me", "/auth/me/"):
        return [r for r in rules if isinstance(rules.get(r), dict)]
    out = []
    for role, role_rules in rules.items():
        if not isinstance(role_rules, dict):
            continue
        allowed = set(role_rules.get("allowed_endpoints", []) or [])
        denied = set(role_rules.get("denied_endpoints", []) or [])
        critical_deny = set(role_rules.get("critical_deny", []) or [])
        if _in_endpoints(method, path, denied) or _in_endpoints(method, path, critical_deny):
            continue
        if _in_endpoints(method, path, allowed):
            out.append(role)
    return sorted(out)


def _is_resource_scoped_endpoint(path: str) -> bool:
    """
    Detect endpoints that are resource-scoped (self-only access).
    These endpoints should only allow access to resources owned by the authenticated user.
    
    Patterns detected:
    - /attachments/{item_id}/* - Employee can only access their own attachments
    - /change-request/{id}/* - Employee can only access their own change requests (detail endpoints)
    
    Returns True if the endpoint should be treated as self-only.
    """
    import re
    path_lower = (path or "").lower()
    
    # Pattern 1: /employee/attachments/{item_id}/* endpoints
    if re.search(r"/employee/attachments/\{[^}]*\}", path_lower):
        return True
    
    # Pattern 2: Detail endpoints with specific ID parameter (not list endpoints)
    # e.g., /employee/change-request/{id_change_request} but not /employee/change-request
    if "/employee/" in path_lower and "{" in path_lower:
        # Only if it's a detail endpoint (has ID parameter after the resource name)
        if re.search(r"/change-request/\{[^}]*\}", path_lower):
            return True
    
    return False

def expected_status(policy, tc: TestCase) -> Dict[str, Any]:
    # Public/auth endpoints - always accessible, can return 200 (success) or 401 (invalid/missing credentials)
    # These endpoints should be accessible regardless of authentication state
    public_endpoints = [
        '/auth/login',
        '/auth/login/',
        '/auth/register',
        '/auth/register/',
        '/auth/refresh',
        '/auth/refresh/',
        '/auth/logout',
        '/auth/logout/',
        '/login',
        '/login/',
        '/refresh',
        '/refresh/',
        '/logout',
        '/logout/',
    ]
    path_normalized = normalize_path(tc.path)
    if any(path_normalized == normalize_path(pub) for pub in public_endpoints):
        ok = _success_statuses_for_method(tc.method)
        # Accept both 200 (success) and 401 (invalid/missing credentials) as valid for public endpoints
        # But 403 (forbidden) is not expected for public endpoints
        return {"status_in": ok + [401], "status_not_in": [403]}

    # /auth/me/ returns current user profile for any authenticated role (no "self" vs "other").
    # Expected 200; not a vulnerability when allowed.
    if path_normalized in ("/auth/me", "/auth/me/"):
        ok = _success_statuses_for_method(tc.method)
        return {"status_in": ok, "status_not_in": [401, 403]}

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
            ok = _success_statuses_for_method(tc.method)
            return {"status_in": ok, "status_not_in":[401,403,404]} if exp else {"status_in":[401,403,404], "status_not_in": ok}
    # Format B: rbac_rules with allowed_endpoints per-role (assume self allowed, other denied)
    if "rbac_rules" in policy:
        allowed, denied, critical_deny, self_only = _policy_allowed_endpoints(policy, tc.role)
        # Fetch role permissions (if any) to infer admin-wide access
        role_rules = (policy.get("rbac_rules", {}) or {}).get(tc.role) or {}
        perms = set(role_rules.get("permissions", []) or [])
        if _in_endpoints(tc.method, tc.path, critical_deny) or _in_endpoints(tc.method, tc.path, denied):
            return {"status_in":[401,403,404], "status_not_in":[200]}
        if _in_endpoints(tc.method, tc.path, allowed):
            # If role has 'rbac_admin', treat access as allowed regardless of self/other for allowed endpoints
            if "rbac_admin" in perms:
                ok = _success_statuses_for_method(tc.method)
                return {"status_in": ok, "status_not_in":[401,403]}

            # Check if endpoint is resource-scoped (self-only access pattern)
            is_resource_scoped = _is_resource_scoped_endpoint(tc.path)
            # Non-admin roles: endpoints with {user_id}, {leave_id}, etc. are self-only (other → expect deny)
            is_id_scoped = has_id_param(tc.path) and ("rbac_admin" not in perms)
            is_self_only = _in_endpoints(tc.method, tc.path, self_only) or is_resource_scoped or is_id_scoped

            # If endpoint is not resource-owner specific (no {id}-like), allow for both self/other
            if not has_id_param(tc.path):
                ok = _success_statuses_for_method(tc.method)
                return {"status_in": ok, "status_not_in":[401,403]}

            # For explicitly self-scoped endpoints (or ID-scoped for non-admin):
            # - self_access=True (baseline, own resource) → expect 200
            # - self_access=False (IDOR, other's resource) → expect 403/404 (TN, not FP)
            if is_self_only:
                ok = _success_statuses_for_method(tc.method)
                return {"status_in": ok, "status_not_in":[401,403]} if tc.self_access else {"status_in":[401,403,404], "status_not_in": ok}

            # For ID-like endpoints without explicit self-only rule, do not assume deny on "other".
            # This avoids false vulnerability labels on endpoints that are legitimately cross-resource.
            ok = _success_statuses_for_method(tc.method)
            return {"status_in": ok, "status_not_in":[401,403]}
        # If endpoint not explicitly allowed or critically denied for this role,
        # follow least-privilege: treat as denied by default.
        ok = _success_statuses_for_method(tc.method)
        return {"status_in":[401,403,404], "status_not_in": ok}
    # default: unknown
    # Conservative default: treat as denied unless explicitly allowed
    ok = _success_statuses_for_method(tc.method)
    return {"status_in":[401,403,404], "status_not_in": ok}

def classify(exp: Dict[str, Any], actual_status: int) -> str:
    def _as_int(v, default=-1):
        try:
            return int(v)
        except Exception:
            return default

    def _is_2xx(v: int) -> bool:
        return 200 <= int(v) < 300

    def _expected_mode(status_in: set) -> str:
        has_allow = any(_is_2xx(s) for s in status_in)
        has_deny = any(s in {401, 403, 404} for s in status_in)
        if has_allow and not has_deny:
            return "allow"
        if has_deny and not has_allow:
            return "deny"
        return "mixed"

    sc = _as_int(actual_status, default=-1)
    if sc == 0:
        return "SKIP"
    if 500 <= sc <= 599:
        return "ERROR"

    status_in = set(_as_int(s) for s in (exp or {}).get("status_in", []))
    status_in.discard(-1)
    mode = _expected_mode(status_in)

    # Input/data quality errors are inconclusive for authz labeling.
    if sc in _STATUS_RULES.get("non_finding", set([400, 409, 422])):
        return "SKIP"

    if mode == "allow":
        if _is_2xx(sc):
            return "TP_ALLOW"
        if sc in {401, 403}:
            return "FP"
        if sc in _STATUS_RULES.get("not_found", set([404])):
            return "NOT_FOUND"
        return "SKIP"

    if mode == "deny":
        if sc in {401, 403, 404}:
            return "TN"
        if _is_2xx(sc):
            return "FN"
        return "SKIP"

    # Mixed/unknown expectation fallback
    if sc in status_in:
        if _is_2xx(sc):
            return "TP_ALLOW"
        if sc in {401, 403, 404}:
            return "TN"
        return "SKIP"
    if _is_2xx(sc) and any(s in {401, 403, 404} for s in status_in):
        return "FN"
    if sc in {401, 403} and any(_is_2xx(s) for s in status_in):
        return "FP"
    if sc in _STATUS_RULES.get("not_found", set([404])):
        return "NOT_FOUND"
    return "SKIP"

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
        "SKIP": c.get("SKIP",0),
    }

def metrics(cf: Dict[str, int]) -> Dict[str, float]:
    TP, FP, FN, TN = cf["TP"], cf["FP"], cf["FN"], cf["TN"]

    # Standard classification metrics on evaluated labels only (TP/FP/FN/TN).
    precision = TP / (TP + FP) if (TP+FP)>0 else 0.0
    recall = TP / (TP + FN) if (TP+FN)>0 else 0.0
    f1 = 2*precision*recall/(precision+recall) if (precision+recall)>0 else 0.0
    evaluated = TP + TN + FP + FN
    acc = (TP + TN) / max(1, evaluated)

    # Security-oriented companion metrics (do not overwrite standard fields).
    block_precision = TN / (TN + FP) if (TN + FP) > 0 else 0.0
    block_recall = TN / (TN + FN) if (TN + FN) > 0 else 0.0
    false_alarm_rate = FP / (FP + TN) if (FP + TN) > 0 else 0.0

    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "accuracy": round(acc, 3),
        "evaluated_cases": int(evaluated),
        "block_precision": round(block_precision, 3),
        "block_recall": round(block_recall, 3),
        "false_alarm_rate": round(false_alarm_rate, 3),
    }

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
