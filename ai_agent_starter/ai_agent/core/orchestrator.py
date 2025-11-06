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

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env from current directory or parent
except ImportError:
    pass  # python-dotenv not installed, skip

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

def _load_adjustments() -> Dict[str, Any]:
    """Parse adjustment.txt rules for safe CRUD flows and delete guards.
    Supported (free-text, Indonesian):
      - "id consent ... tidak boleh di hapus" -> deny_delete['consent']
      - "id consent ... boleh di hapus" -> allow_delete['consent']
      - "permission_id ... jangan di hapus" -> deny_delete['permission']
      - "permission_id ... boleh di hapus" -> allow_delete['permission']
      - "role_id ... jangan di hapus" -> deny_delete['role']
      - "role_id ... boleh di hapus" -> allow_delete['role']
    """
    import re
    path = Path('adjustment.txt')
    # Also try project root
    if not path.exists():
        alt = Path.cwd() / 'adjustment.txt'
        path = alt if alt.exists() else None
    rules = {"allow_delete": {"consent": [], "permission": [], "role": []},
             "deny_delete": {"consent": [], "permission": [], "role": []}}
    if not path:
        # Try repo path in parent
        parent = Path(__file__).resolve().parents[3] / 'adjustment.txt'
        if parent.exists():
            path = parent
    try:
        if path and path.exists():
            txt = path.read_text(encoding='utf-8')
            def nums(s):
                return [int(x) for x in re.findall(r"\b(\d+)\b", s)]
            for line in txt.splitlines():
                ll = line.strip().lower()
                if 'consent' in ll:
                    if 'tidak boleh' in ll or 'jangan' in ll:
                        rules['deny_delete']['consent'] += nums(ll)
                    if 'boleh di hapus' in ll or 'boleh hapus' in ll or 'boleh dihapus' in ll:
                        rules['allow_delete']['consent'] += nums(ll)
                if 'permission_id' in ll or 'permission' in ll:
                    if 'tidak boleh' in ll or 'jangan' in ll:
                        rules['deny_delete']['permission'] += nums(ll)
                    if 'boleh di hapus' in ll or 'boleh hapus' in ll or 'boleh dihapus' in ll:
                        rules['allow_delete']['permission'] += nums(ll)
                if 'role_id' in ll or re.search(r"\brole\b", ll):
                    if 'tidak boleh' in ll or 'jangan' in ll:
                        rules['deny_delete']['role'] += nums(ll)
                    if 'boleh di hapus' in ll or 'boleh hapus' in ll or 'boleh dihapus' in ll:
                        rules['allow_delete']['role'] += nums(ll)
    except Exception:
        pass
    # Dedup
    for k in ['allow_delete','deny_delete']:
        for rk in ['consent','permission','role']:
            rules[k][rk] = sorted({int(x) for x in rules[k][rk] if isinstance(x,int)})
    return rules

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

def execute(memory: Memory, http: HttpClient, auth: AuthManager, policy: dict, tests: List[TestCase] = None, concurrency: int = 1, adjustments: Dict[str, Any] = None, openapi: dict = None, delay_s: float = 0.0):
    batch = tests if tests is not None else memory.tests
    # Build OpenAPI set for fast membership checks (method, path)
    openapi_set = set()
    if isinstance(openapi, dict) and openapi.get('paths'):
        try:
            openapi_set = {(e["method"].upper(), normalize_path(e["path"])) for e in extract_paths_from_openapi(openapi)}
        except Exception:
            openapi_set = set()

    def _determine_bac_type(tc: TestCase) -> str:
        """
        Determine BAC type for artifact organization:
        - 'auth': authentication/login endpoints
        - 'horizontal': IDOR - same privilege level, accessing other user's resources
        - 'vertical': BOLA - privilege escalation attempt
        - 'baseline': normal expected operations (self access)
        """
        mut = tc.mutation or {}
        
        # Check if it's an auth endpoint
        path_lower = tc.path.lower()
        if any(keyword in path_lower for keyword in ['/auth/', '/login', '/logout', '/token', '/refresh']):
            return 'auth'
        
        # Check mutation type
        mut_type = str(mut.get("type", "")).upper()
        
        # Vertical escalation (privilege escalation)
        if mut_type in ("BOLA", "VERTICAL", "ESCALATION"):
            return 'vertical'
        if mut.get("as_role") and mut.get("as_role") != tc.role:
            return 'vertical'
        
        # Horizontal access (IDOR - other user's resource at same level)
        if mut_type == "IDOR" or mut.get("variant") == "other":
            return 'horizontal'
        if not tc.self_access:
            return 'horizontal'
        
        # Check for no-auth attempts (treat as vertical since it's trying to bypass auth)
        if mut.get("no_auth") or mut.get("without_auth") or mut_type in ("NO_AUTH", "NEGATIVE_AUTH"):
            return 'vertical'
        
        # Default baseline (self access, normal operations)
        return 'baseline'

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

    def _scan_id_candidates(body: Any) -> Dict[str, int]:
        """
        Extract candidate id-like fields from a JSON-ish body.
        Returns mapping of key -> int value for keys containing 'id'.
        """
        out: Dict[str, int] = {}
        try:
            def _add_from_obj(obj: Dict[str, Any]):
                for k, v in (obj or {}).items():
                    if not isinstance(k, str):
                        continue
                    kl = k.lower()
                    if 'id' in kl:
                        try:
                            iv = int(v)
                            out[k] = iv
                        except Exception:
                            pass

            def _first_items(val: Any):
                # typical wrappers
                if isinstance(val, dict):
                    for path in [
                        ['data', 'items'], ['data', 'list'], ['data', 'results'],
                        ['items'], ['list'], ['results'], ['data']
                    ]:
                        cur = val
                        ok = True
                        for key in path:
                            if isinstance(cur, dict) and key in cur:
                                cur = cur[key]
                            else:
                                ok = False
                                break
                        if ok and isinstance(cur, list):
                            return cur[:3]
                        if ok and isinstance(cur, dict):
                            return [cur]
                if isinstance(val, list):
                    return val[:3]
                if isinstance(val, dict):
                    return [val]
                return []

            # scan wrappers and top-level
            for item in _first_items(body):
                if isinstance(item, dict):
                    _add_from_obj(item)
            if isinstance(body, dict):
                _add_from_obj(body)
        except Exception:
            return out
        return out

    def _learn_ids_from_response(tc: TestCase, resp_body: Any, owner_role: str):
        """
        Learn/store resource IDs per-role from a response body, aligned to placeholders in tc.path.
        """
        try:
            # gather candidates from body
            cands = _scan_id_candidates(resp_body)
            if not cands:
                return
            # placeholders present in the original path template
            placeholders = _extract_placeholders(tc.path)
            for ph in placeholders:
                base = ph
                if base.endswith('_id'):
                    base = base[:-3]
                if base.startswith('id_'):
                    base = base[3:]
                # try exact matches first, then common variants
                keys_try = [ph, base, f"{base}_id", f"id_{base}"]
                rid = None
                for k in keys_try:
                    if k in cands:
                        rid = cands[k]
                        break
                # fallback: pick strongest candidate whose key contains the base token
                if rid is None:
                    for k, v in cands.items():
                        if base and base.lower() in k.lower():
                            rid = v
                            break
                if rid is not None and isinstance(rid, int) and rid > 0:
                    memory.store_resource_id(owner_role, base, rid)
        except Exception:
            return

    def _resource_key_from_path(path: str) -> str | None:
        pl = (path or '').lower()
        if '/consent' in pl:
            return 'consent'
        if '/permissions' in pl or '/permission' in pl:
            return 'permission'
        if re.search(r"/(role|roles)(/|$)", pl):
            return 'role'
        if '/employee/change-request' in pl:
            return 'change_request'
        return None

    def _extract_target_id_from_path(path: str) -> int | None:
        try:
            m = re.search(r"/(\d+)(?:$|[/?#])", path)
            return int(m.group(1)) if m else None
        except Exception:
            return None

    def _run_one(tc: TestCase):
        mut = tc.mutation or {}
        # Tentukan role/token yang dipakai (support eskalasi percobaan via mutation.as_role)
        as_role = mut.get("as_role") or tc.role
        use_no_auth = str(mut.get("no_auth") or mut.get("without_auth") or "false").lower() in ("true", "1", "yes") or str(mut.get("type")).upper() in ("NO_AUTH", "NEGATIVE_AUTH")
        token = None if use_no_auth else auth.get_token(as_role)

        # Mutasi path: ganti {id}-like
        path = _fill_placeholders(tc.path, as_role, tc.self_access)

        # Repair path against OpenAPI if needed (handle missing leading slash or stray prefix artifacts)
        try:
            m = (tc.method or 'GET').upper()
            p = normalize_path(path)
            if openapi_set and (m, p) not in openapi_set:
                # Try removing any non-slash prefix before first '/'
                raw = p.lstrip('\ufeff').strip()
                if not raw.startswith('/'):
                    raw = '/' + raw
                # Drop leading non-slash segment if it's not in OpenAPI (e.g., stray 'I2/')
                if '/' in raw[1:]:
                    candidate = '/' + raw.split('/', 2)[2] if raw.count('/') >= 2 else raw
                    cand_norm = normalize_path(candidate)
                    if (m, cand_norm) in openapi_set:
                        p = cand_norm
                # Last attempt: keep normalized original
            path = p
        except Exception:
            # keep original path best effort
            pass

        # Special case: assign role to user -> enforce user_id=112 and JSON body
        try:
            if str(tc.method).upper() == 'POST' and '/user/' in path and '/roles' in path:
                fixed_uid = 112
                # normalize any placeholder or numeric segment to 112 for /user/{user_id}/roles
                path = re.sub(r"(/user/)(?:\d+|\{[^}/]+\})(/roles)", fr"\1{fixed_uid}\2", path)
                # enforce minimal body for role assignment
                mut.setdefault('json', {})
                if isinstance(mut['json'], dict):
                    mut['json'].update({"id_role": 1, "role_name": "Admin_HC"})
        except Exception:
            pass

        # Kirim request
        # Query param duplication for ID injection
        params = None
        if mut.get("query_id"):
            params = {"id": _target_user_id(as_role, tc.self_access)}

        # Extra headers and method override
        extra_headers = {}
        if isinstance(mut.get("headers"), dict):
            extra_headers.update(mut.get("headers"))

        # Determine BAC type for artifact organization
        bac_type = _determine_bac_type(tc)
        
        # Build test context for metadata
        test_context = {
            "self_access": tc.self_access,
            "mutation": mut,
            "depth": tc.depth,
            "as_role": as_role,
            "original_role": tc.role,
            "use_no_auth": use_no_auth
        }

        json_body = mut.get("json") if isinstance(mut.get("json"), dict) else None
        # Auto-generate minimal JSON body from OpenAPI schema if needed
        if json_body is None and str(tc.method).upper() in ("POST","PUT","PATCH") and isinstance(openapi, dict):
            try:
                def _req_schema(oas: dict, pth: str, m: str):
                    try:
                        node = (oas.get('paths', {}) or {}).get(pth) or {}
                        op = node.get(m.lower()) or node.get(m.upper()) or {}
                        rb = (op.get('requestBody') or {}).get('content', {})
                        app = rb.get('application/json') or rb.get('application/x-www-form-urlencoded') or {}
                        return app.get('schema') or {}
                    except Exception:
                        return {}
                def _minimal(schema: dict):
                    if not isinstance(schema, dict):
                        return None
                    # Resolve simple allOf/oneOf first element
                    for comb in ('allOf','oneOf','anyOf'):
                        if isinstance(schema.get(comb), list) and schema.get(comb):
                            return _minimal(schema.get(comb)[0])
                    t = (schema.get('type') or '').lower()
                    if '$ref' in schema:
                        # no resolver; fallback to object
                        t = t or 'object'
                    if t == 'object' or ('properties' in schema):
                        props = schema.get('properties') or {}
                        req = schema.get('required') or []
                        body = {}
                        for k in req:
                            pt = (props.get(k, {}).get('type') or '').lower()
                            if pt == 'string' or pt == '':
                                body[k] = "test"
                            elif pt in ('integer','number'):
                                body[k] = 1
                            elif pt == 'boolean':
                                body[k] = False
                            elif pt == 'array':
                                body[k] = []
                            elif pt == 'object':
                                body[k] = {}
                            else:
                                body[k] = "test"
                        return body or None
                    return None
                schema = _req_schema(openapi, tc.path, tc.method)
                if not schema and isinstance(adjustments, dict):
                    # Attempt lookup by normalized path (strip numbers -> {id})
                    try:
                        templ = re.sub(r"/(\d+)(?:$|/)", "/{id}", tc.path)
                        schema = _req_schema(openapi, templ, tc.method)
                    except Exception:
                        pass
                json_body = _minimal(schema)
                # Special case: change_request draft for PUT flow
                if '/employee/change-request' in tc.path.lower() and str(tc.method).upper() == 'POST':
                    if isinstance(json_body, dict) and 'submit' in json_body:
                        json_body['submit'] = False
                if mut.get('json') and isinstance(mut.get('json'), dict):
                    # Allow explicit override from mutation
                    json_body = mut.get('json')
            except Exception:
                json_body = None

        # Guard for sensitive DELETE based on adjustments
        if str(tc.method).upper() == 'DELETE' and isinstance(adjustments, dict):
            rkey = _resource_key_from_path(tc.path)
            tid = _extract_target_id_from_path(path)
            if rkey and tid is not None:
                allow_set = set(adjustments.get('allow_delete', {}).get(rkey, []))
                deny_set = set(adjustments.get('deny_delete', {}).get(rkey, []))
                # Skip delete if explicitly denied
                if tid in deny_set:
                    # record skip
                    import time as _t
                    memory.record_result(Result(tc=tc, status_code=0, body={"skipped": True, "reason": "protected id (deny_delete)"}, ts=_t.time(), artifact=None))
                    return
                # If allow list exists, only allow when in allow_set
                if allow_set and tid not in allow_set:
                    import time as _t
                    memory.record_result(Result(tc=tc, status_code=0, body={"skipped": True, "reason": "id not in allow_delete"}, ts=_t.time(), artifact=None))
                    return

        # Realtime progress: before request
        try:
            print(f"[RUN] role={tc.role} | type={bac_type.upper()} | {tc.method} {path}")
        except Exception:
            pass

        resp = http.request(
            tc.method, 
            path, 
            token=token, 
            params=params, 
            extra_headers=extra_headers,
            json_body=json_body,
            role=tc.role,
            bac_type=bac_type,
            test_context=test_context
        )
        import time as _t
        memory.record_result(Result(tc=tc, status_code=resp["status_code"], body=resp.get("body", {}), ts=_t.time(), artifact=resp.get("artifact")))
        # Realtime progress: after request
        try:
            print(f"[RES] role={tc.role} | type={bac_type.upper()} | {tc.method} {path} -> {resp['status_code']} | artifact={resp.get('artifact')}")
        except Exception:
            pass
        # Optional slow mode between requests
        try:
            if delay_s and delay_s > 0:
                time.sleep(delay_s)
        except Exception:
            pass
        # If created a resource, mark it for potential cleanup logic and store ids for placeholders
        try:
            if str(tc.method).upper() == 'POST':
                rkey = _resource_key_from_path(tc.path)
                cands = _scan_id_candidates(resp.get('body', {}))
                # map resource -> common placeholder keys
                placeholder_keys = {
                    'permission': ['id_permission', 'permission_id', 'id'],
                    'role': ['role_id', 'id_role', 'id'],
                    'consent': ['id_consent', 'consent_id', 'id'],
                    'change_request': ['id_change_request', 'change_request_id', 'id'],
                }
                if rkey and isinstance(cands, dict) and cands:
                    keys = placeholder_keys.get(rkey, ['id'])
                    rid_val = None
                    for field in keys:
                        if field in cands:
                            rid_val = cands[field]
                            break
                    if rid_val is None and 'id' in cands:
                        rid_val = cands['id']
                    if isinstance(rid_val, int) and rid_val > 0:
                        memory.mark_created(rkey, as_role, rid_val)
                        # Store into resource_ids for future placeholder filling
                        for k in keys:
                            base = k
                            if base.endswith('_id'):
                                base = base[:-3]
                            if base.startswith('id_'):
                                base = base[3:]
                            memory.store_resource_id(as_role, base, rid_val)
        except Exception:
            pass
        # Learn IDs from response to improve future placeholder filling
        try:
            owner_role = as_role if tc.self_access else (f"{as_role}_2" if hasattr(auth, 'roles') and f"{as_role}_2" in auth.roles else as_role)
            _learn_ids_from_response(tc, resp.get('body', {}), owner_role)
        except Exception:
            pass

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
    from ai_agent.core.evaluators import expected_status, bac_type
    observations = []
    for r in results:
        exp = expected_status(policy, r.tc)
        verdict = "ok" if r.status_code in exp.get("status_in", []) else "mismatch"
        vuln = verdict == "mismatch" and r.status_code == 200
        # Prepare a redacted, bounded body excerpt to safely share with LLM
        try:
            import json as _json
            body_text = _json.dumps(r.body, ensure_ascii=False) if isinstance(r.body, (dict, list)) else str(r.body)
        except Exception:
            body_text = str(r.body)
        body_excerpt = _redact_str(body_text, max_chars=800)
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
            "bac_type": bac_type(policy, r.tc),
            "body_excerpt": body_excerpt,
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

def _triage_llm_redacted(client, provider: str, observations: List[Dict[str, Any]], max_items: int = 50, redact_max_chars: int = 1000) -> Dict[str, Any]:
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
            # Provide a safe, short excerpt for context
            "body_excerpt": _redact_str(str(o.get("body_excerpt") or ""), max_chars=redact_max_chars),
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

def _followups_llm(client, provider: str, observations: List[Dict[str, Any]], current_depth: int, max_add: int = 10, redact_max_chars: int = 1000) -> List[Dict[str, Any]]:
    # Only use mismatches as seeds
    seeds = []
    for o in observations:
        if not o.get("vuln_suspected"):
            continue
        seeds.append({
            "method": o.get("method"),
            "path": o.get("path"),
            "role": o.get("role"),
            "self_access": o.get("self_access"),
            "mutation": o.get("mutation"),
            "observed_status": o.get("actual"),
            # Include a short redacted excerpt to help propose smarter variants
            "body_excerpt": _redact_str(str(o.get("body_excerpt") or ""), max_chars=redact_max_chars),
        })
    if not seeds:
        return []
    import json as _json
    prompt = (
        "You are an API security tester agent focusing on BAC/IDOR.\n"
        "Given failed observations (expected deny vs actual 200 or vice versa), propose up to "
        f"{max_add} follow-up test variants with fields: method, path, role, variant (self/other), headers (optional), no_auth (optional true/false), query_id (optional true).\n"
        "Return strictly JSON with key 'tests' as array.\n\n"
        f"Seeds (with redacted body excerpts):\n{_json.dumps(seeds, ensure_ascii=False)}\n"
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
        data = _json.loads(content or "{}")
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

    def _plan_from_policy(self, policy: dict, roles: list, openapi: dict | None) -> tuple[list[dict], list[dict]]:
        """Policy-first plan: build endpoint list from policy allowed_endpoints/critical_deny across the given roles.
        Returns (plan_pairs, endpoints_list_for_report).
        """
        # Collect endpoints per policy
        eps = endpoints_from_policy(policy)  # unique set across roles
        if openapi and isinstance(openapi, dict) and openapi.get('paths'):
            # keep only ones present in OpenAPI if available
            oset = {(e["method"].upper(), normalize_path(e["path"])) for e in extract_paths_from_openapi(openapi)}
            eps = [e for e in eps if (e["method"].upper(), normalize_path(e["path"])) in oset]
        # Keep order by method preference GET->POST->PUT->DELETE
        order = {"GET":0, "POST":1, "PUT":2, "PATCH":3, "DELETE":4}
        eps_sorted = sorted(eps, key=lambda e: (order.get((e.get('method') or 'GET').upper(), 9), normalize_path(e.get('path') or '/')))
        # Limit to TOP_N_ENDPOINTS to avoid explosion
        eps_sorted = eps_sorted[:TOP_N_ENDPOINTS]
        # Build plan pairs per role: self and other for IDOR coverage
        plan: list[dict] = []
        for e in eps_sorted:
            m = (e.get('method') or 'GET').upper()
            p = normalize_path(e.get('path') or '/')
            for r in roles:
                plan.append({"method": m, "path": p, "role": r, "self_access": True})
                plan.append({"method": m, "path": p, "role": r, "self_access": False})
        return plan, eps_sorted

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

    def _generate_summary_recommendations(self, cf: Dict[str, int], m: Dict[str, float], cov: Dict[str, Any], results: List[Result], policy: dict, vulns: int) -> str:
        """Generate comprehensive LLM-based security assessment summary and actionable recommendations."""
        try:
            # Load summarizer prompt
            prompt_path = Path(__file__).parent.parent / "prompts" / "summarizer.md"
            if not prompt_path.exists():
                return "⚠️ Summary generation skipped (prompt template not found)"
            
            prompt_template = prompt_path.read_text(encoding="utf-8")
            
            # Collect vulnerability details
            from .evaluators import expected_status, classify
            vulnerabilities_list = []
            for r in results:
                exp = expected_status(policy, r.tc)
                lab = classify(exp, r.status_code)
                if lab == "FN":  # False Negative = Vulnerability
                    vulnerabilities_list.append({
                        "method": r.tc.method,
                        "path": r.tc.path,
                        "role": r.tc.role,
                        "status": r.status_code,
                        "expected": "403/401 (Deny)",
                        "actual": "200 (Allow)",
                        "type": r.tc.mutation.get("type", "Unknown") if r.tc.mutation else "Unknown"
                    })
            
            # Format vulnerabilities for prompt
            vuln_text = ""
            if vulnerabilities_list:
                vuln_text = "\n".join([
                    f"- **{v['method']} {v['path']}** (Role: {v['role']}, Type: {v['type']})\n  - Expected: {v['expected']}, Got: {v['actual']}"
                    for v in vulnerabilities_list
                ])
            else:
                vuln_text = "✅ No vulnerabilities detected (all unauthorized access attempts were correctly blocked)"
            
            # Fill prompt template
            fp_rate = round((cf.get("FP", 0) / max(1, cf.get("FP", 0) + cf.get("TN", 0))) * 100, 1)
            
            prompt = prompt_template.format(
                total_tests=len(results),
                accuracy=round(m.get("accuracy", 0) * 100, 1),
                precision=round(m.get("precision", 0) * 100, 1),
                recall=round(m.get("recall", 0) * 100, 1),
                f1=round(m.get("f1", 0) * 100, 1),
                fp_rate=fp_rate,
                tp=cf.get("TP", 0),
                tn=cf.get("TN", 0),
                fp=cf.get("FP", 0),
                fn=cf.get("FN", 0),
                err=cf.get("ERR", 0),
                nf=cf.get("NF", 0),
                endpoints=cov.get("endpoints", 0),
                roles=cov.get("roles", 0),
                total_pairs=cov.get("total_pairs", 0),
                tested_pairs=cov.get("tested_pairs", 0),
                coverage=cov.get("coverage_pct", 0),
                vulnerabilities_list=vuln_text
            )
            
            # Call LLM
            if self.llm_provider == "google_genai" and genai:
                model = genai.GenerativeModel(self.llm_model)
                response = model.generate_content(prompt)
                return response.text
            elif self.llm_provider == "openai" and self.client:
                response = self.client.chat.completions.create(
                    model=self.llm_model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,
                    max_tokens=2000
                )
                return response.choices[0].message.content
            else:
                return "⚠️ LLM summary unavailable (provider not configured)"
        
        except Exception as e:
            return f"⚠️ Summary generation failed: {str(e)}"

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
        # Keep Admin_HC, Employee, and Employee_2 when available
        wanted = ["Admin_HC","Employee","Employee_2"]
        roles = [r for r in roles if r in wanted]

        # Planning mode: policy-first (best practice) or default
        planning = (agent.get('planning') or {}) if isinstance(agent, dict) else {}
        policy_first = bool(planning.get('policy_first', True))

        if policy_first:
            plan_list, endpoints = self._plan_from_policy(policy, roles, openapi)
        else:
            # Try LLM plan, fallback to deterministic plan via OpenAPI/config/policy
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

        # Append best-practice CRUD flows in safe order based on adjustments
        try:
            self._append_crud_flows(openapi, memory, available_auth_roles)
        except Exception:
            pass

        # EXECUTE/OBSERVE/REFLECT with depth iterations
        max_depth = int(agent.get("depth", 1))
        llm_cfg = agent.get("llm", {}) if isinstance(agent, dict) else {}
        triage_enabled = bool(llm_cfg.get("triage_enabled")) and bool(self.client)
        followups_enabled = bool(llm_cfg.get("followups_enabled")) and bool(self.client)
        redact_enabled = bool(llm_cfg.get("redact_enabled", True))
        redact_max_chars = int(llm_cfg.get("redact_max_chars", 1000))
        # Load adjustments (safe delete lists) and enforce sequential execution for learning
        adjustments = _load_adjustments()
        forced_conc = 1

        # Determine slow mode delay from config or env
        try:
            delay_ms = int(os.getenv('REQUEST_DELAY_MS') or agent.get('request_delay_ms') or 0)
        except Exception:
            delay_ms = 0
        delay_s = max(0.0, float(delay_ms) / 1000.0)

        for cur_depth in range(0, max_depth):
            # execute tests at current depth only
            pending = [t for t in memory.tests if t.depth == cur_depth]
            if not pending and cur_depth > 0:
                break
            # Order pending: Employee (self) → Employee_2 → Admin → others; then GET→POST→PUT→DELETE; then self before other
            def _role_rank(r: str) -> int:
                rl = (r or '').lower()
                if rl == 'employee':
                    return 0
                if rl == 'employee_2':
                    return 1
                if rl == 'admin_hc':
                    return 2
                return 3
            def _method_rank(m: str) -> int:
                order = {'GET':0,'POST':1,'PUT':2,'DELETE':3}
                return order.get((m or '').upper(), 9)
            pending.sort(key=lambda x: (_role_rank(getattr(x,'role',"")), _method_rank(getattr(x,'method',"")), 0 if getattr(x,'self_access',True) else 1))
            # Run
            execute(memory, http, auth, policy, tests=pending, concurrency=forced_conc, adjustments=adjustments, openapi=openapi, delay_s=delay_s)
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
                        llm_fus = _followups_llm(self.client, self.llm_provider, obs_cur, cur_depth, redact_max_chars=redact_max_chars)
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
                reflection = _triage_llm_redacted(self.client, self.llm_provider, observations_all, redact_max_chars=redact_max_chars)
            except Exception:
                reflection = reflect(observations_all)
        else:
            reflection = reflect(observations_all)

        # Generate comprehensive LLM summary & recommendations
        from .evaluators import confusion_counts, metrics as _metrics, coverage as _coverage
        cf = confusion_counts(memory.results, policy)
        m = _metrics(cf)
        cov = _coverage(memory.tests, roles, endpoints)
        vulns = int(cf.get("FN", 0))
        
        llm_summary = self._generate_summary_recommendations(
            cf, m, cov, memory.results, policy, vulns
        )

        # Generate professional report filename with descriptive naming
        # Format: BAC_Security_Test_Report-YYYY-MM-DD_HH-MM-SS.json
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        report_name = f"BAC_Security_Test_Report-{timestamp}.json"
        report_path = os.path.join(self.runs_dir, report_name)
        save_json_report(report_path, memory.results, policy, memory.tests, roles, endpoints, start_ts=start_ts, reflection=reflection, llm_summary=llm_summary)
        
        # Print summary to console
        print("\n" + "="*80)
        print("🤖 AI SECURITY ASSESSMENT SUMMARY")
        print("="*80)
        print(llm_summary)
        print("="*80)
        print(f"\n📄 Full report saved to: {report_path}")
        print(f"📊 Markdown summary: {report_path.replace('.json', '.md')}\n")
        
        return {
            "total_tests": len(memory.tests),
            "vulnerabilities": vulns,
            "report_path": report_path,
            "reflection": reflection,
            "llm_summary": llm_summary,
            "metrics": m,
        }

    # --- Best-practice CRUD sequence generator ---
    def _append_crud_flows(self, openapi: dict, memory: Memory, available_roles: List[str]):
        if not isinstance(openapi, dict) or not openapi.get('paths'):
            return
        def has_ep(m, p):
            return (m.upper(), normalize_path(p)) in {(e["method"].upper(), normalize_path(e["path"])) for e in extract_paths_from_openapi(openapi)}
        def choose_role(prefer: str, fallback_first=True):
            if prefer in available_roles:
                return prefer
            return available_roles[0] if (available_roles and fallback_first) else None
        admin = choose_role('Admin_HC') or (available_roles[0] if available_roles else None)
        employee = choose_role('Employee') or (available_roles[0] if available_roles else None)
        employee2 = choose_role('Employee_2', fallback_first=False) or employee

        # permissions
        try:
            seq = []
            if has_ep('GET','/permissions'):
                seq.append(TestCase(method='GET', path='/permissions', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('POST','/permissions'):
                seq.append(TestCase(method='POST', path='/permissions', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('GET','/permission/{id_permission}'):
                seq.append(TestCase(method='GET', path='/permission/{id_permission}', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('PUT','/permission/{id_permission}'):
                seq.append(TestCase(method='PUT', path='/permission/{id_permission}', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('DELETE','/permission/{id_permission}'):
                seq.append(TestCase(method='DELETE', path='/permission/{id_permission}', role=admin, self_access=True, mutation={"type":"baseline"}))
            for tc in seq:
                memory.record_test(tc)
        except Exception:
            pass

        # vertical escalation attempts (BOLA) against admin-ish endpoints using Employee token
        try:
            esc = []
            if employee and has_ep('GET','/roles'):
                esc.append(TestCase(method='GET', path='/roles', role=employee, self_access=True, mutation={"type":"BOLA", "headers": {"X-Role": "Admin_HC"}}))
            if employee and has_ep('GET','/permissions'):
                esc.append(TestCase(method='GET', path='/permissions', role=employee, self_access=True, mutation={"type":"BOLA", "headers": {"X-Role": "Admin_HC"}}))
            if employee and has_ep('GET','/users'):
                esc.append(TestCase(method='GET', path='/users', role=employee, self_access=True, mutation={"type":"BOLA", "headers": {"X-Role": "Admin_HC"}}))
            # also a no-auth escalation probe for one admin endpoint
            if has_ep('GET','/roles'):
                esc.append(TestCase(method='GET', path='/roles', role=employee or admin, self_access=True, mutation={"type":"NO_AUTH", "no_auth": True}))
            for tc in esc:
                memory.record_test(tc)
        except Exception:
            pass

        # roles
        try:
            seq = []
            if has_ep('GET','/roles'):
                seq.append(TestCase(method='GET', path='/roles', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('POST','/roles'):
                seq.append(TestCase(method='POST', path='/roles', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('GET','/role/{id_role}'):
                seq.append(TestCase(method='GET', path='/role/{id_role}', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('PUT','/role/{id_role}'):
                seq.append(TestCase(method='PUT', path='/role/{id_role}', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('DELETE','/role/{id_role}'):
                seq.append(TestCase(method='DELETE', path='/role/{id_role}', role=admin, self_access=True, mutation={"type":"baseline"}))
            for tc in seq:
                memory.record_test(tc)
        except Exception:
            pass

        # consents
        try:
            seq = []
            # list endpoints may vary; prefer /employee/consents/list if present
            if has_ep('GET','/employee/consents/list'):
                seq.append(TestCase(method='GET', path='/employee/consents/list', role=admin, self_access=True, mutation={"type":"baseline"}))
            elif has_ep('GET','/employee/consents/active'):
                seq.append(TestCase(method='GET', path='/employee/consents/active', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('POST','/employee/consents'):
                seq.append(TestCase(method='POST', path='/employee/consents', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('GET','/employee/consents/{id_consent}'):
                seq.append(TestCase(method='GET', path='/employee/consents/{id_consent}', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('PUT','/employee/consents/{id_consent}'):
                seq.append(TestCase(method='PUT', path='/employee/consents/{id_consent}', role=admin, self_access=True, mutation={"type":"baseline"}))
            if has_ep('DELETE','/employee/consents/{id_consent}'):
                seq.append(TestCase(method='DELETE', path='/employee/consents/{id_consent}', role=admin, self_access=True, mutation={"type":"baseline"}))
            for tc in seq:
                memory.record_test(tc)
        except Exception:
            pass

        # change requests (employee flow + IDOR check)
        try:
            seq = []
            if has_ep('GET','/employee/change-request'):
                seq.append(TestCase(method='GET', path='/employee/change-request', role=employee, self_access=True, mutation={"type":"baseline"}))
            if has_ep('POST','/employee/change-request'):
                # draft to enable PUT later
                seq.append(TestCase(method='POST', path='/employee/change-request', role=employee, self_access=True, mutation={"type":"baseline", "json": {"submit": False}}))
            if has_ep('GET','/employee/change-request/{id_change_request}'):
                # self check
                seq.append(TestCase(method='GET', path='/employee/change-request/{id_change_request}', role=employee, self_access=True, mutation={"type":"baseline"}))
                # IDOR check by other employee
                if employee2 and employee2 != employee:
                    seq.append(TestCase(method='GET', path='/employee/change-request/{id_change_request}', role=employee2, self_access=False, mutation={"type":"IDOR", "variant":"other"}))
            if has_ep('PUT','/employee/change-request/{id_change_request}'):
                seq.append(TestCase(method='PUT', path='/employee/change-request/{id_change_request}', role=employee, self_access=True, mutation={"type":"baseline"}))
            # avoid DELETE by default for change-request unless explicitly desired
            for tc in seq:
                memory.record_test(tc)
        except Exception:
            pass
