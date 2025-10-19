import os, time, json
from typing import List, Dict, Any, Tuple
import re
from ai_agent.core.utils import load_yaml, load_json, extract_paths_from_openapi, has_id_param, normalize_path, load_policy
from ai_agent.core.utils import endpoints_from_policy, load_endpoints_config
from ai_agent.core.tools_http import HttpClient
from ai_agent.core.tools_auth import AuthManager
from ai_agent.core.memory import Memory, TestCase, Result
from ai_agent.core.reporters import save_json_report
from ai_agent.core.utils import load_rbac_matrix, get_all_roles, get_role_permissions
import os
from pathlib import Path

try:
    # Optional providers
    from openai import OpenAI
except Exception:
    OpenAI = None
try:
    import google.generativeai as genai
except Exception:
    genai = None

TOP_N_ENDPOINTS = 56

def _endpoint_priority_score(method: str, path: str, openapi: dict) -> int:
    score = 0
    # Prioritas tinggi jika menyentuh identitas/otorisasi
    id_like = ("{id}" in path) or ("{user_id}" in path) or ("{employee_id}" in path)
    keywords = ["auth", "login", "logout", "user", "employee", "role", "permission", "consent"]
    kw_hit = any(k in path.lower() for k in keywords)
    if id_like:
        score += 5
    if kw_hit:
        score += 3
    # Bonus kecil untuk metode tulis yang rawan BAC
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        score += 2
    return score

def plan_tests(openapi: dict, roles: list) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    endpoints = extract_paths_from_openapi(openapi)
    # Prioritaskan endpoint yang punya {id}
    prioritized = [e for e in endpoints if has_id_param(e["path"])]
    if not prioritized:
        prioritized = endpoints
    # Urutkan dengan heuristik prioritas dan batasi ke 56 endpoint unik
    prioritized_sorted = sorted(prioritized, key=lambda e: _endpoint_priority_score(e["method"], e["path"], openapi), reverse=True)
    seen = set()
    top_eps: List[Dict[str, Any]] = []
    for e in prioritized_sorted:
        key = (e["method"].upper(), normalize_path(e["path"]))
        if key in seen:
            continue
        seen.add(key)
        top_eps.append({"method": key[0], "path": key[1]})
        if len(top_eps) >= TOP_N_ENDPOINTS:
            break
    # Buat pasangan role×endpoint (self & other)
    plan = []
    for e in top_eps:
        for r in roles:
            plan.append({"method": e["method"], "path": normalize_path(e["path"]), "role": r, "self_access": True})
            plan.append({"method": e["method"], "path": normalize_path(e["path"]), "role": r, "self_access": False})
    return plan, endpoints

def _extract_placeholders(path: str) -> List[str]:
    return re.findall(r"\{([^}/]+)\}", path or "")

def _discover_ids(http: HttpClient, auth: AuthManager, openapi: dict, memory: Memory, roles: List[str], max_per_role: int = 10):
    paths = openapi.get('paths', {}) if isinstance(openapi, dict) else {}
    # Candidates: GET endpoints ending with a single placeholder, e.g., /resource/{id_something}
    candidates = []
    for p, methods in paths.items():
        get_meta = (methods or {}).get('get') or (methods or {}).get('GET')
        if not get_meta:
            continue
        phs = _extract_placeholders(p)
        if len(phs) != 1:
            continue
        # Only if placeholder at the end segment
        if not re.search(r"/\{[^}/]+\}$", p):
            continue
        placeholder = phs[0]
        # Derive list path by stripping the trailing /{placeholder}
        list_path = re.sub(r"/\{[^}/]+\}$", "", p)
        if list_path == p or not list_path:
            continue
        candidates.append({"detail_path": normalize_path(p), "list_path": normalize_path(list_path), "placeholder": placeholder})

    # De-duplicate by list_path
    seen = set()
    uniq = []
    for c in candidates:
        key = (c['list_path'], c['placeholder'])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)

    def _first_item(body: Dict[str, Any]):
        try:
            # common shapes
            for path in [
                ['data', 'items'],
                ['data', 'list'],
                ['data', 'results'],
                ['items'],
                ['list'],
                ['results'],
                ['data'],
            ]:
                cur = body
                ok = True
                for k in path:
                    if isinstance(cur, dict) and k in cur:
                        cur = cur[k]
                    else:
                        ok = False
                        break
                if ok and isinstance(cur, list) and cur:
                    return cur[0]
            # body itself is a list
            if isinstance(body, list) and body:
                return body[0]
        except Exception:
            return None
        return None

    def _pick_id_key(item: Dict[str, Any]) -> Tuple[str, int]:
        if not isinstance(item, dict):
            return None, None
        # Prefer exact 'id'
        if 'id' in item:
            try:
                return 'id', int(item['id'])
            except Exception:
                pass
        # Otherwise pick key that contains 'id'
        for k, v in item.items():
            if 'id' in str(k).lower():
                try:
                    return k, int(v)
                except Exception:
                    continue
        return None, None

    for role in roles:
        stored = 0
        try:
            token = auth.get_token(role)
        except Exception:
            continue
        for c in uniq:
            if stored >= max_per_role:
                break
            try:
                resp = http.request('GET', c['list_path'], token=token)
                item = _first_item(resp.get('body', {}))
                key, rid = _pick_id_key(item)
                if rid is not None:
                    # store under placeholder name base for convenience
                    base = c['placeholder']
                    # normalize common patterns so future fill works regardless of exact variant
                    if base.startswith('id_'):
                        base = base[3:]
                    if base.endswith('_id'):
                        base = base[:-3]
                    memory.store_resource_id(role, base, rid)
                    stored += 1
            except Exception:
                continue

def _replace_id_placeholders(path: str, target_id: int) -> str:
    def repl(m):
        name = m.group(1)
        # legacy behavior (kept for compatibility)
        if name == 'id' or name.endswith('_id') or name in ("user_id", "employee_id") or ('id' in name.lower()):
            return str(target_id)
        return m.group(0)
    return re.sub(r"\{([^}/]+)\}", repl, path)

def execute(memory: Memory, http: HttpClient, auth: AuthManager, policy: dict, tests: List[TestCase] = None, concurrency: int = 1):
    batch = tests if tests is not None else memory.tests

    def _target_user_id(as_role: str, self_access: bool) -> int:
        uid = auth.get_user_id(as_role)
        if not self_access:
            alt_role = f"{as_role}_2"
            if hasattr(auth, 'roles') and alt_role in auth.roles:
                alt_uid = auth.get_user_id(alt_role)
                return alt_uid if isinstance(alt_uid, int) and alt_uid > 0 else uid + 1
            return uid + 1
        return uid

    def _lookup_resource_id(owner_role: str, placeholder: str) -> int | None:
        # Try exact placeholder, then normalized variants
        if owner_role in memory.resource_ids:
            rid_map = memory.resource_ids[owner_role]
            if placeholder in rid_map:
                return rid_map[placeholder]
            base = placeholder
            if placeholder.endswith('_id'):
                base = placeholder[:-3]
            if placeholder.startswith('id_'):
                base = placeholder[3:]
            for key in (base, f"{base}_id", f"id_{base}"):
                if key in rid_map:
                    return rid_map[key]
        return None

    def _fill_placeholders(path: str, as_role: str, self_access: bool) -> str:
        # Decide owner role for resource-bound placeholders
        owner_role = as_role if self_access else (f"{as_role}_2" if hasattr(auth, 'roles') and f"{as_role}_2" in auth.roles else as_role)
        # Compute default user-centric target id for fallback
        target_id = _target_user_id(as_role, self_access)

        def repl(m):
            name = m.group(1)
            # If placeholder looks user-id-like, use target user id
            if name == 'id' or name in ("user_id", "employee_id") or name.endswith('_id') and ('user' in name.lower() or 'employee' in name.lower()):
                return str(target_id)
            # Try resource-specific id from seeded fixtures
            rid = _lookup_resource_id(owner_role, name)
            if rid is not None:
                return str(rid)
            # If generally id-like, fallback to user target id
            if 'id' in name.lower():
                return str(target_id)
            return m.group(0)

        return re.sub(r"\{([^}/]+)\}", repl, path)

    def _run_one(tc: TestCase):
        mut = tc.mutation or {}
        # Tentukan role/token yang dipakai (support eskalasi percobaan via mutation.as_role)
        as_role = mut.get("as_role") or tc.role
        use_no_auth = str(mut.get("no_auth") or mut.get("without_auth") or "false").lower() in ("true", "1", "yes") or str(mut.get("type")).upper() in ("NO_AUTH", "NEGATIVE_AUTH")
        token = None if use_no_auth else auth.get_token(as_role)

        # Mutasi path: ganti {id}-like
        path = _fill_placeholders(tc.path, as_role, tc.self_access)

        # Kirim request
        # Query param duplication for ID injection
        params = None
        if mut.get("query_id"):
            params = {"id": _target_user_id(as_role, tc.self_access)}

        # Extra headers and method override
        extra_headers = {}
        if isinstance(mut.get("headers"), dict):
            extra_headers.update(mut.get("headers"))

        resp = http.request(tc.method, path, token=token, params=params, extra_headers=extra_headers)
        import time as _t
        memory.record_result(Result(tc=tc, status_code=resp["status_code"], body=resp.get("body", {}), ts=_t.time(), artifact=resp.get("artifact")))

    if concurrency and concurrency > 1:
        try:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                list(ex.map(_run_one, batch))
        except Exception:
            for tc in batch:
                _run_one(tc)
    else:
        for tc in batch:
            _run_one(tc)

def generate(plan_items: List[Dict[str, Any]], policy: dict) -> List[TestCase]:
    """Generate: turunkan TestCase dari rencana (bisa diperluas untuk mutasi vertikal/horizontal)."""
    cases: List[TestCase] = []
    for item in plan_items:
        cases.append(TestCase(**item))
    return cases

def _policy_context_for_role(policy: dict, role: str) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"role": role, "allowed_endpoints": [], "critical_deny": []}
    if not isinstance(policy, dict):
        return ctx
    rr = policy.get("rbac_rules", {}).get(role) or {}
    if rr:
        ctx["allowed_endpoints"] = rr.get("allowed_endpoints", []) or []
        ctx["critical_deny"] = rr.get("critical_deny", []) or []
    return ctx

def generate_llm(client, plan_pairs: List[Dict[str, Any]], policy: dict, openapi: dict, model: str) -> List[TestCase]:
    """Minta LLM membuat test spec per endpoint×role, termasuk mutasi IDOR/BOLA, lalu konversi ke TestCase."""
    # Siapkan payload ringkas agar hemat token
    unique_pairs = []
    seen = set()
    for p in plan_pairs:
        key = (p["method"].upper(), normalize_path(p["path"]), p["role"])  # tanpa self_access di sini
        if key in seen:
            continue
        seen.add(key)
        unique_pairs.append({"method": key[0], "path": key[1], "role": key[2]})

    # Siapkan policy ringkas per role
    roles = sorted(set([p["role"] for p in unique_pairs]))
    policy_ctx = {r: _policy_context_for_role(policy, r) for r in roles}

    try:
        template = Path('ai_agent/prompts/tester.md').read_text(encoding='utf-8')
    except Exception:
        template = "You are a test generator. Return JSON with tests array."
    import json as _json
    prompt = (
        f"{template}\n\n" 
        f"Pairs:\n{_json.dumps(unique_pairs, ensure_ascii=False)}\n\n"
        f"PolicyByRole:\n{_json.dumps(policy_ctx, ensure_ascii=False)}\n\n"
        "Instructions: For each (method,path,role), generate: baseline self and an IDOR mutation to other user's id when path has {id}-like param; add vertical/permission-escalation attempts when endpoint looks admin (roles/permissions/users). Return JSON: {\"tests\":[{\"method\",\"path\",\"role\",\"mutations\":[{\"type\":\"IDOR|BOLA\",\"field\":\"...\",\"variant\":\"self|other|escalate\"}],\"expected\":{...}}]}"
    )

    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.2,
            top_p=0.1,
            max_tokens=2000,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You are a focused API security test generator. Stay strictly on Broken Access Control (IDOR/BOLA). Use only provided pairs and roles. Output JSON only."},
                {"role": "user", "content": prompt}
            ],
        )
        content = resp.choices[0].message.content
        data = _json.loads(content)
        tests = data.get("tests") or []
    except Exception:
        return []

    cases: List[TestCase] = []
    # Build OpenAPI endpoint set for filtering
    openapi_set = {(e["method"].upper(), normalize_path(e["path"])) for e in extract_paths_from_openapi(openapi)}
    allowed_methods = {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"}
    for t in tests:
        m = (t.get("method") or "GET").upper()
        if m not in allowed_methods:
            continue
        pth_raw = t.get("path") or t.get("endpoint") or "/"
        pth = normalize_path(pth_raw if pth_raw.startswith('/') else '/' + pth_raw)
        # Keep only endpoints present in OpenAPI to avoid off-topic
        if (m, pth) not in openapi_set:
            continue
        role = t.get("role") or (roles[0] if roles else "Employee")
        mutations = t.get("mutations") or []
        # baseline self
        cases.append(TestCase(method=m, path=pth, role=role, self_access=True, mutation={"type":"baseline"}))
        # from mutations, derive self/other (limit to a few per pair)
        for mut in mutations[:3]:
            v = str(mut.get("variant") or mut.get("scope") or "other").lower()
            if v in ("self", "own", "me"):
                cases.append(TestCase(method=m, path=pth, role=role, self_access=True, mutation=mut))
            else:
                cases.append(TestCase(method=m, path=pth, role=role, self_access=False, mutation=mut))
    return cases

def observe(results: List[Result], policy: dict) -> List[Dict[str, Any]]:
    """Observe: bandingkan hasil dengan ekspektasi kebijakan untuk temuan ringkas."""
    from .evaluators import expected_status
    observations = []
    for r in results:
        exp = expected_status(policy, r.tc)
        verdict = "ok" if r.status_code in exp.get("status_in", []) else "mismatch"
        vuln = verdict == "mismatch" and r.status_code == 200
        observations.append({
            "method": r.tc.method,
            "path": r.tc.path,
            "role": r.tc.role,
            "self_access": r.tc.self_access,
            "expected": exp,
            "actual": r.status_code,
            "vuln_suspected": bool(vuln),
            "depth": getattr(r.tc, 'depth', 0),
            "mutation": r.tc.mutation,
        })
    return observations

def reflect(observations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Reflect: simpulkan insight singkat dan rencana perbaikan/lanjutan (stub)."""
    total = len(observations)
    mismatches = [o for o in observations if o.get("vuln_suspected")]
    notes = []
    if not total:
        notes.append("No tests executed")
    if mismatches:
        notes.append(f"Potential BAC issues: {len(mismatches)} candidates")
    else:
        notes.append("No potential BAC from current sample")
    return {"total": total, "potential_vulns": len(mismatches), "notes": notes}

def _redact_str(val: str, max_chars: int = 1000) -> str:
    try:
        s = str(val)
    except Exception:
        return ""
    # basic truncation
    if len(s) > max_chars:
        s = s[:max_chars] + "..."
    # simple patterns: emails, tokens-like, long numbers
    import re
    s = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<redacted:email>", s)
    s = re.sub(r"(?i)authorization:\s*\S+", "Authorization: <redacted>", s)
    s = re.sub(r"(?i)bearer\s+[A-Za-z0-9._-]+", "Bearer <redacted>", s)
    s = re.sub(r"\b\d{9,}\b", "<redacted:number>", s)
    return s

def _triage_llm_redacted(client, provider: str, observations: List[Dict[str, Any]], max_items: int = 50) -> Dict[str, Any]:
    items = []
    for o in observations[:max_items]:
        items.append({
            "method": o.get("method"),
            "path": o.get("path"),
            "role": o.get("role"),
            "self": o.get("self_access"),
            "expected": o.get("expected"),
            "actual": o.get("actual"),
            "mutation": o.get("mutation"),
        })
    import json as _json
    prompt = (
        "You are an API security triage assistant focused on Broken Access Control (IDOR/BOLA).\n"
        "Given a JSON array of observation items with expected and actual status, summarize:\n"
        "- probable root causes (e.g., missing ownership checks, role mixups)\n"
        "- prioritized next actions (what to test next)\n"
        "Return strictly JSON with keys: summary, suspected_causes, next_actions.\n\n"
        f"Observations:\n{_json.dumps(items, ensure_ascii=False)}"
    )
    try:
        if provider == "gemini":
            resp = client.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
            content = getattr(resp, "text", None)
            if not content and getattr(resp, "candidates", None):
                try:
                    content = resp.candidates[0].content.parts[0].text
                except Exception:
                    content = "{}"
        else:
            resp = client.chat.completions.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                temperature=0.2,
                top_p=0.1,
                max_tokens=1000,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "You are an API security triage assistant. Return JSON only."},
                    {"role": "user", "content": prompt}
                ]
            )
            content = resp.choices[0].message.content
        import json as _json
        data = _json.loads(content or "{}")
        if isinstance(data, dict):
            return data
        return {"summary": "", "suspected_causes": [], "next_actions": []}
    except Exception:
        return {"summary": "", "suspected_causes": [], "next_actions": []}

def _followups_llm(client, provider: str, observations: List[Dict[str, Any]], current_depth: int, max_add: int = 10) -> List[Dict[str, Any]]:
    # Only use mismatches as seeds
    seeds = [
        {k: o.get(k) for k in ("method", "path", "role", "self_access", "mutation")}
        for o in observations if o.get("vuln_suspected")
    ]
    if not seeds:
        return []
    import json as _json
    prompt = (
        "You are an API security tester agent focusing on BAC/IDOR.\n"
        "Given failed observations (expected deny vs actual 200 or vice versa), propose up to "
        f"{max_add} follow-up test variants with fields: method, path, role, variant (self/other), headers (optional), no_auth (optional true/false), query_id (optional true).\n"
        "Return strictly JSON with key 'tests' as array.\n\n"
        f"Seeds:\n{_json.dumps(seeds, ensure_ascii=False)}\n"
    )
    try:
        if provider == "gemini":
            resp = client.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
            content = getattr(resp, "text", None)
            if not content and getattr(resp, "candidates", None):
                try:
                    content = resp.candidates[0].content.parts[0].text
                except Exception:
                    content = "{}"
        else:
            resp = client.chat.completions.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                temperature=0.2,
                top_p=0.1,
                max_tokens=1200,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "You generate follow-up API tests. Return JSON with 'tests' only."},
                    {"role": "user", "content": prompt}
                ]
            )
            content = resp.choices[0].message.content
        data = json.loads(content or "{}")
        tests = data.get("tests") or []
        out = []
        for t in tests[:max_add]:
            m = (t.get("method") or "GET").upper()
            path = normalize_path('/' + str(t.get("path") or t.get("endpoint") or '/').lstrip('/'))
            role = t.get("role") or seeds[0].get("role")
            variant = str(t.get("variant") or "other").lower()
            self_access = variant in ("self", "own", "me")
            mut = {}
            if t.get("headers"): mut["headers"] = t.get("headers")
            if t.get("no_auth") is True: mut["no_auth"] = True
            if t.get("query_id") is True: mut["query_id"] = True
            out.append({"method": m, "path": path, "role": role, "self_access": self_access, "depth": current_depth+1, "mutation": mut})
        return out
    except Exception:
        return []

def _next_methods(method: str) -> List[str]:
    # Simple rotation for method override attempts
    order = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    m = method.upper()
    if m not in order:
        return [m]
    idx = order.index(m)
    return [order[(idx+1) % len(order)]]

def generate_followups(observations: List[Dict[str, Any]], available_roles: List[str], current_depth: int, max_depth: int) -> List[TestCase]:
    """Buat test-case lanjutan saat hasil tak sesuai kebijakan (IDOR/BOLA) hingga depth tertentu.
    Variasi: no-auth, method override header, duplicate id query, role spoof header.
    """
    if current_depth >= max_depth:
        return []
    followups: List[TestCase] = []
    for o in observations:
        if not o.get("vuln_suspected"):
            continue
        base = {
            "method": o["method"],
            "path": o["path"],
            "role": o["role"],
            "self_access": o["self_access"],
            "depth": current_depth + 1,
        }
        # 1) No-auth retry (jika belum no-auth)
        followups.append(TestCase(**{**base, "mutation": {"type": "NO_AUTH", "no_auth": True}}))
        # 2) Method override header (X-HTTP-Method-Override)
        for nm in _next_methods(o["method"]):
            followups.append(TestCase(**{**base, "mutation": {"type": "METHOD_OVERRIDE", "headers": {"X-HTTP-Method-Override": nm}}}))
        # 3) Duplicate ID in querystring
        followups.append(TestCase(**{**base, "mutation": {"type": "QUERY_INJECTION", "query_id": True}}))
        # 4) Role spoofing header (X-Role)
        target_role = "Admin_HC" if "Admin_HC" in available_roles else (available_roles[0] if available_roles else o["role"])
        followups.append(TestCase(**{**base, "mutation": {"type": "ROLE_SPOOF", "headers": {"X-Role": target_role}}}))
    return followups

def main(config_dir="ai_agent/config", data_dir="ai_agent/data", runs_dir="ai_agent/runs"):
    agent = load_yaml(os.path.join(config_dir, "agent.yaml"))
    policy = load_policy(config_dir)
    auth_cfg = load_yaml(os.path.join(config_dir, "auth.yaml"))
    # OpenAPI is optional. If missing, main() will fallback to policy/endpoints.yaml
    try:
        openapi = load_json(os.path.join(data_dir, "openapi.json"))
    except Exception:
        openapi = {}

    # Token header/type from auth config
    _tok = (auth_cfg or {}).get("token", {}) if isinstance(auth_cfg, dict) else {}
    # Allow env override for base_url (useful for local runs)
    _base_url = os.getenv("API_BASE_URL") or agent["base_url"]
    http = HttpClient(
        base_url=_base_url,
        timeout_s=agent["timeout_s"],
        retries=agent["retries"],
        artifacts_dir=agent["artifacts_dir"],
        dry_run=agent.get("dry_run", False),
        token_header=_tok.get("header", "Authorization"),
        token_type=_tok.get("type", "Bearer"),
    )
    auth = AuthManager(http=http, auth_cfg=auth_cfg, openapi=openapi)

    roles = policy.get("roles", [])
    if not roles:
        # Fallback to known roles from CSV or auth config
        try:
            roles = get_all_roles()
        except Exception:
            roles = []
        if not roles:
            rcfg = auth_cfg.get("roles", {})
            if isinstance(rcfg, dict):
                roles = list(rcfg.keys())
            elif isinstance(rcfg, list):
                roles = [r.get("name") for r in rcfg if isinstance(r, dict) and r.get("name")]
    # Build endpoints source: prefer OpenAPI; else combine endpoints.yaml and policy
    if isinstance(openapi, dict) and openapi.get('paths'):
        plan, endpoints = plan_tests(openapi, roles)
    else:
        # derive endpoints without OpenAPI
        eps_cfg = load_endpoints_config(config_dir)
        eps_pol = endpoints_from_policy(policy)
        endpoints = (eps_cfg or []) + [e for e in eps_pol if e not in (eps_cfg or [])]
        # If still empty, no targets
        # Build plan directly from endpoints list
        top_eps = endpoints[:TOP_N_ENDPOINTS]
        plan = []
        for e in top_eps:
            for r in roles:
                plan.append({"method": e["method"], "path": normalize_path(e["path"]), "role": r, "self_access": True})
                plan.append({"method": e["method"], "path": normalize_path(e["path"]), "role": r, "self_access": False})

    memory = Memory()
    for item in plan:
        memory.record_test(TestCase(**item))

    execute(memory, http, auth, policy, concurrency=int(agent.get("concurrency", 1)))

    ts = time.strftime("%Y%m%d-%H%M%S")
    report_path = os.path.join(runs_dir, f"report-{ts}.json")
    save_json_report(report_path, memory.results, policy, memory.tests, roles, endpoints)
    return report_path

if __name__ == "__main__":
    p = main()
    print("Report saved to:", p)


class AgentOrchestrator:
    def __init__(self, config_dir: str = "ai_agent/config", data_dir: str = "ai_agent/data", runs_dir: str = "ai_agent/runs"):
        self.config_dir = config_dir
        self.data_dir = data_dir
        self.runs_dir = runs_dir
        # Optional LLM client (OpenAI or Gemini)
        self.client = None
        self.llm_provider = (os.getenv("LLM_PROVIDER") or "openai").strip().lower()
        if self.llm_provider == "gemini" and genai and os.getenv("GEMINI_API_KEY"):
            try:
                genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
                self.gemini_model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
                self.client = genai.GenerativeModel(self.gemini_model_name)
            except Exception:
                self.client = None
        elif self.llm_provider in ("openai", "") and OpenAI and os.getenv("OPENAI_API_KEY"):
            try:
                self.client = OpenAI()
                self.llm_provider = "openai"
            except Exception:
                self.client = None
        # Tabular RBAC (optional for planner prompt)
        try:
            self.rbac_matrix = load_rbac_matrix()
        except Exception:
            self.rbac_matrix = None
        try:
            self.roles = get_all_roles()
        except Exception:
            self.roles = []

    def _load_openapi(self) -> dict:
        return load_json(os.path.join(self.data_dir, "openapi.json"))

    def _plan_tests_llm(self, openapi: dict, fallback_roles: list) -> List[Dict[str, Any]]:
        if not self.client:
            return None
        try:
            roles = fallback_roles or self.roles
            rbac_text = ""
            if self.rbac_matrix is not None:
                try:
                    rbac_text = self.rbac_matrix.to_markdown(index=False)
                except Exception:
                    rbac_text = str(self.rbac_matrix.head(20))
            prompt_template = Path('ai_agent/prompts/planner.md').read_text(encoding='utf-8')
            prompt = prompt_template.format(
                openapi_json=openapi,
                rbac_matrix=rbac_text,
                roles=", ".join(roles)
            )
            if self.llm_provider == "gemini":
                # Request JSON output
                resp = self.client.generate_content(prompt, generation_config={
                    "response_mime_type": "application/json"
                })
                content = getattr(resp, "text", None) or (resp.candidates[0].content.parts[0].text if getattr(resp, "candidates", None) else "{}")
            else:
                resp = self.client.chat.completions.create(
                    model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    temperature=0.2,
                    top_p=0.1,
                    max_tokens=1500,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": "You are a focused API security planner. Stay strictly on Broken Access Control (IDOR/BOLA). Use only the provided OpenAPI and roles. Return JSON only."},
                        {"role": "user", "content": prompt}
                    ]
                )
                content = resp.choices[0].message.content
            # Expect JSON with "tests" array of dicts
            import json as _json
            data = _json.loads(content)
            items = data.get("tests") or data.get("items") or []
            # Normalisasi dan pilih 56 endpoint unik dengan prioritas identitas/otorisasi
            norm_eps = []
            for it in items:
                m = (it.get("method") or "GET").upper()
                if m not in {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"}:
                    continue
                p_raw = it.get("path") or it.get("endpoint") or "/"
                p = normalize_path(p_raw if str(p_raw).startswith('/') else '/' + str(p_raw))
                norm_eps.append({"method": m, "path": p})
            # Jika LLM tak memberi cukup konteks, fallback ke semua dari OpenAPI
            if not norm_eps:
                norm_eps = extract_paths_from_openapi(openapi)
            # Filter agar hanya endpoint yang ada di OpenAPI
            openapi_set = {(e["method"].upper(), normalize_path(e["path"])) for e in extract_paths_from_openapi(openapi)}
            norm_eps = [e for e in norm_eps if (e["method"], e["path"]) in openapi_set]
            # Skor + deduplikasi
            sorted_eps = sorted(norm_eps, key=lambda e: _endpoint_priority_score(e["method"], e["path"], openapi), reverse=True)
            seen = set()
            selected = []
            for e in sorted_eps:
                key = (e["method"], e["path"])
                if key in seen:
                    continue
                seen.add(key)
                selected.append(e)
                if len(selected) >= TOP_N_ENDPOINTS:
                    break
            # Bentuk rencana final untuk semua roles, self & other
            plan = []
            for e in selected:
                for r in roles:
                    plan.append({"method": e["method"], "path": e["path"], "role": r, "self_access": True})
                    plan.append({"method": e["method"], "path": e["path"], "role": r, "self_access": False})
            return plan
        except Exception:
            return None

    def _generate_llm(self, plan_pairs: List[Dict[str, Any]], policy: dict, openapi: dict) -> List[TestCase]:
        """LLM-based generation of test cases using tester.md; returns empty on failure."""
        if not self.client:
            return []
        # Deduplicate pairs
        unique_pairs = []
        seen = set()
        for p in plan_pairs:
            key = (p["method"].upper(), normalize_path(p["path"]), p["role"])  # without self flag
            if key in seen:
                continue
            seen.add(key)
            unique_pairs.append({"method": key[0], "path": key[1], "role": key[2]})
        roles = sorted(set([p["role"] for p in unique_pairs]))
        policy_ctx = {r: _policy_context_for_role(policy, r) for r in roles}
        try:
            template = Path('ai_agent/prompts/tester.md').read_text(encoding='utf-8')
        except Exception:
            template = "You are a test generator. Return JSON with tests array."
        import json as _json
        prompt = (
            f"{template}\n\n" 
            f"Pairs:\n{_json.dumps(unique_pairs, ensure_ascii=False)}\n\n"
            f"PolicyByRole:\n{_json.dumps(policy_ctx, ensure_ascii=False)}\n\n"
            f"Return JSON with key 'tests'."
        )
        try:
            if self.llm_provider == "gemini":
                resp = self.client.generate_content(prompt, generation_config={
                    "response_mime_type": "application/json"
                })
                content = getattr(resp, "text", None) or (resp.candidates[0].content.parts[0].text if getattr(resp, "candidates", None) else "{}")
            else:
                resp = self.client.chat.completions.create(
                    model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    temperature=0.2,
                    top_p=0.1,
                    max_tokens=2000,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": "You are a focused API security test generator. Return JSON only with a 'tests' array."},
                        {"role": "user", "content": prompt}
                    ]
                )
                content = resp.choices[0].message.content
            data = _json.loads(content)
            tests = data.get("tests") or []
            # Normalize and limit per pair
            # Convert into TestCase baseline + mutations
            cases: List[TestCase] = []
            openapi_set = {(e["method"].upper(), normalize_path(e["path"])) for e in extract_paths_from_openapi(openapi)}
            for t in tests:
                m = (t.get("method") or "GET").upper()
                p_raw = t.get("path") or t.get("endpoint") or "/"
                pth = normalize_path(p_raw if str(p_raw).startswith('/') else '/' + str(p_raw))
                if (m, pth) not in openapi_set:
                    continue
                role = t.get("role") or (roles[0] if roles else "Employee")
                mutations = t.get("mutations") or []
                cases.append(TestCase(method=m, path=pth, role=role, self_access=True, mutation={"type":"baseline"}))
                for mut in mutations[:3]:
                    v = str(mut.get("variant") or mut.get("scope") or "other").lower()
                    if v in ("self", "own", "me"):
                        cases.append(TestCase(method=m, path=pth, role=role, self_access=True, mutation=mut))
                    else:
                        cases.append(TestCase(method=m, path=pth, role=role, self_access=False, mutation=mut))
            return cases
        except Exception:
            return []

    def run(self) -> dict:
        agent = load_yaml(os.path.join(self.config_dir, "agent.yaml"))
        start_ts = time.time()
        policy = load_policy(self.config_dir)
        auth_cfg = load_yaml(os.path.join(self.config_dir, "auth.yaml"))
        # OpenAPI optional
        try:
            openapi = self._load_openapi()
        except Exception:
            openapi = {}

        _tok = (auth_cfg or {}).get("token", {}) if isinstance(auth_cfg, dict) else {}
        _base_url = os.getenv("API_BASE_URL") or agent["base_url"]
        http = HttpClient(
            base_url=_base_url,
            timeout_s=agent.get("timeout_s", 20),
            retries=agent.get("retries", 1),
            artifacts_dir=agent.get("artifacts_dir", "ai_agent/runs/artifacts"),
            dry_run=agent.get("dry_run", False),
            token_header=_tok.get("header", "Authorization"),
            token_type=_tok.get("type", "Bearer"),
        )
        auth = AuthManager(http=http, auth_cfg=auth_cfg, openapi=openapi)

        available_auth_roles = list(auth.roles.keys())
        # Also consider roles that have env-based credentials even if not declared in auth.yaml
        # Use candidate roles from policy/self/auth to avoid referencing undefined variable
        try:
            from .tools_auth import AuthManager as _AM
            candidate_roles = (policy.get("roles") or self.roles or list(auth.roles.keys()))
            for r in (candidate_roles or []):
                if r in available_auth_roles:
                    continue
                base = _AM._env_key_base(r)
                u = os.getenv(f"{base}_USERNAME")
                p = os.getenv(f"{base}_PASSWORD")
                if u or p:
                    available_auth_roles.append(r)
        except Exception:
            pass

        # Prepare memory and optionally seed fixtures to create resources and capture IDs per role
        memory = Memory()
        def _extract_path(obj: Dict[str, Any], path: str):
            cur = obj
            for key in (path or "").split('.'):
                if isinstance(cur, dict) and key in cur:
                    cur = cur[key]
                else:
                    return None
            return cur

        fixtures = agent.get("fixtures") or []
        if isinstance(fixtures, list) and fixtures:
            for fx in fixtures:
                if not isinstance(fx, dict):
                    continue
                role = fx.get("role") or fx.get("as_role")
                method = (fx.get("method") or "POST").upper()
                path = fx.get("path") or fx.get("endpoint")
                if not role or not path:
                    continue
                json_body = fx.get("json") or fx.get("body")
                id_path = fx.get("id_json_path") or fx.get("id_path")
                store_as = fx.get("store_as") or fx.get("resource") or "resource"
                try:
                    token = auth.get_token(role)
                    resp = http.request(method, path, token=token, json_body=json_body)
                    rid = None
                    if id_path:
                        rid = _extract_path(resp.get("body", {}), id_path)
                    if rid is None:
                        # Heuristic fallbacks
                        rid = _extract_path(resp.get("body", {}), "data.id") or resp.get("body", {}).get("id")
                    if isinstance(rid, (int, str)):
                        try:
                            rid_int = int(rid)
                        except Exception:
                            rid_int = None
                        if rid_int is not None:
                            memory.store_resource_id(role, store_as, rid_int)
                            # Also store using common placeholder variants
                            memory.store_resource_id(role, f"{store_as}_id", rid_int)
                            memory.store_resource_id(role, f"id_{store_as}", rid_int)
                except Exception:
                    # Continue even if a fixture fails
                    pass
        # Best-practice: auto-discover IDs from list endpoints for simple {id_*} detail paths
        disc = agent.get("discovery") or {}
        if bool(disc.get("enabled", True)):
            try:
                _discover_ids(http, auth, openapi, memory, roles, max_per_role=int(disc.get("max_per_role", 10)))
            except Exception:
                pass
        roles = policy.get("roles") or self.roles or available_auth_roles
        # Filter to roles we can actually authenticate (from auth.yaml or env creds), or allow all in dry_run
        if not agent.get("dry_run", False):
            roles = [r for r in roles if r in available_auth_roles]

        # Try LLM plan, fallback to deterministic plan
        llm_plan = self._plan_tests_llm(openapi, roles)
        if llm_plan:
            # When no OpenAPI, we still need endpoints for coverage/reporting
            if isinstance(openapi, dict) and openapi.get('paths'):
                endpoints = extract_paths_from_openapi(openapi)
            else:
                eps_cfg = load_endpoints_config(self.config_dir)
                eps_pol = endpoints_from_policy(policy)
                endpoints = (eps_cfg or []) + [e for e in eps_pol if e not in (eps_cfg or [])]
            plan_list = llm_plan
        else:
            if isinstance(openapi, dict) and openapi.get('paths'):
                plan_list, endpoints = plan_tests(openapi, roles)
            else:
                eps_cfg = load_endpoints_config(self.config_dir)
                eps_pol = endpoints_from_policy(policy)
                endpoints = (eps_cfg or []) + [e for e in eps_pol if e not in (eps_cfg or [])]
                # Deterministic plan from endpoints
                plan_list = []
                for e in endpoints[:TOP_N_ENDPOINTS]:
                    for r in roles:
                        plan_list.append({"method": e["method"], "path": normalize_path(e["path"]), "role": r, "self_access": True})
                        plan_list.append({"method": e["method"], "path": normalize_path(e["path"]), "role": r, "self_access": False})

        # GENERATE (LLM, fallback deterministic)
        generated = []
        if self.client:
            try:
                generated = self._generate_llm(plan_list, policy, openapi)
            except Exception:
                generated = []
        if not generated:
            generated = generate(plan_list, policy)
        # memory may already contain fixture IDs
        for tc in generated:
            memory.record_test(tc)

        # EXECUTE/OBSERVE/REFLECT with depth iterations
        max_depth = int(agent.get("depth", 1))
        llm_cfg = agent.get("llm", {}) if isinstance(agent, dict) else {}
        triage_enabled = bool(llm_cfg.get("triage_enabled")) and bool(self.client)
        followups_enabled = bool(llm_cfg.get("followups_enabled")) and bool(self.client)
        redact_enabled = bool(llm_cfg.get("redact_enabled", True))
        redact_max_chars = int(llm_cfg.get("redact_max_chars", 1000))
        for cur_depth in range(0, max_depth):
            # execute tests at current depth only
            pending = [t for t in memory.tests if t.depth == cur_depth]
            if not pending and cur_depth > 0:
                break
            # Run
            execute(memory, http, auth, policy, tests=pending, concurrency=int(agent.get("concurrency", 1)))
            # Observe
            observations = observe(memory.results, policy)
            # Generate follow-ups if any
            if cur_depth < max_depth - 1:
                # Filter observations of current depth only
                obs_cur = [o for o in observations if o.get("depth") == cur_depth]
                followups = generate_followups(obs_cur, available_auth_roles, cur_depth, max_depth)
                # Optional: LLM-driven follow-ups (redacted observations only)
                if followups_enabled:
                    try:
                        llm_fus = _followups_llm(self.client, self.llm_provider, obs_cur, cur_depth)
                    except Exception:
                        llm_fus = []
                    # Merge with cap to avoid explosion
                    followups.extend(llm_fus[:10])
                for f in followups:
                    memory.record_test(f)
        # Final reflect over all observations across all depths
        observations_all = observe(memory.results, policy)
        if triage_enabled:
            try:
                reflection = _triage_llm_redacted(self.client, self.llm_provider, observations_all)
            except Exception:
                reflection = reflect(observations_all)
        else:
            reflection = reflect(observations_all)

        ts = time.strftime("%Y%m%d-%H%M%S")
        report_path = os.path.join(self.runs_dir, f"report-{ts}.json")
        save_json_report(report_path, memory.results, policy, memory.tests, roles, endpoints, start_ts=start_ts, reflection=reflection)

        # Summarize
        from .evaluators import confusion_counts
        cf = confusion_counts(memory.results, policy)
        vulns = int(cf.get("FN", 0))
        return {
            "total_tests": len(memory.tests),
            "vulnerabilities": vulns,
            "report_path": report_path,
            "reflection": reflection,
        }
