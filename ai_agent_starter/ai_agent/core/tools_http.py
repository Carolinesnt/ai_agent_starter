import os, time, json, pathlib, requests, random
from urllib.parse import urlsplit
from typing import Dict, Any, Optional

class HttpClient:
    def __init__(self, base_url: str, timeout_s: int=20, retries: int=1, artifacts_dir: str="ai_agent/runs/artifacts", dry_run: bool=False,
                 token_header: str = "Authorization", token_type: str = "Bearer"):
        self.base_url = base_url.rstrip('/')
        self.timeout_s = timeout_s
        self.retries = retries
        self.artifacts_dir = artifacts_dir
        self.dry_run = dry_run
        self.token_header = token_header or "Authorization"
        self.token_type = token_type or "Bearer"
        # Cache for live value discovery from API lists.
        self._value_probe_cache: Dict[str, Any] = {}
        pathlib.Path(artifacts_dir).mkdir(parents=True, exist_ok=True)
        self.session = None if dry_run else requests.Session()

    @staticmethod
    def _safe_segment(value: str, fallback: str = "unknown", max_len: int = 72) -> str:
        """Create filesystem-safe path segment with bounded length."""
        try:
            s = str(value or "").strip().lower()
            if not s:
                s = fallback
            # Keep alnum + separators only.
            cleaned = []
            for ch in s:
                if ch.isalnum() or ch in ("_", "-", "."):
                    cleaned.append(ch)
                elif ch in ("/", "\\", " ", ":", "?", "&", "="):
                    cleaned.append("_")
            s = "".join(cleaned).strip("._-")
            while "__" in s:
                s = s.replace("__", "_")
            if not s:
                s = fallback
            return s[:max_len]
        except Exception:
            return fallback

    def _artifact_path(
        self,
        name: str,
        role: str = None,
        bac_type: str = None,
        target_label: str | None = None,
        method: str | None = None,
        path: str | None = None,
    ) -> str:
        """
        Generate organized artifact path structure:
        artifacts/
          {role}/
            horizontal/  (IDOR - same privilege level, different user)
            vertical/    (BOLA - privilege escalation)
            baseline/    (normal expected operations)
            auth/        (authentication related)
        """
        # Group by date to keep runs tidy and easy to inspect.
        day_folder = time.strftime("%Y_%m_%d")
        if role:
            # Normalize role name for folder (lowercase, replace spaces/special chars)
            role_folder = self._safe_segment(role, fallback="unknown_role")
            
            # Determine subfolder based on BAC type, mapped to expected labels
            bt = (bac_type or "baseline").strip().lower()
            label = (
                "IDOR" if bt == "horizontal" else
                "BOLA" if bt == "vertical" else
                "AUTH" if bt == "auth" else
                "BASELINE"
            )
            
            # Optional target label (e.g., to_admin, to_employee, to_same_role)
            parts = [self.artifacts_dir, day_folder, role_folder, label]
            if target_label:
                safe_target = self._safe_segment(target_label, fallback="to_unknown")
                parts.append(safe_target)
            # Method split (GET/POST/PUT/etc.)
            if method:
                parts.append(self._safe_segment(method.upper(), fallback="UNKNOWN_METHOD", max_len=16))
            # Endpoint split (users_id, payroll, auth_login, etc.)
            if path:
                endpoint_key = str(path or "").strip().strip("/")
                endpoint_key = endpoint_key.replace("{", "").replace("}", "")
                endpoint_key = endpoint_key.replace("/", "_")
                parts.append(self._safe_segment(endpoint_key, fallback="root_endpoint"))

            # Create directory structure
            full_dir = os.path.join(*parts)
            pathlib.Path(full_dir).mkdir(parents=True, exist_ok=True)
            return os.path.join(full_dir, name)
        else:
            # Fallback to flat structure if no role provided
            return os.path.join(self.artifacts_dir, day_folder, name)

    def _mask_headers_for_artifact(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        masked = dict(headers or {})
        # Mask common and configured auth header
        header_keys = {"authorization", "Authorization", self.token_header, self.token_header.lower()}
        auth = None
        for k in header_keys:
            if k in masked and isinstance(masked.get(k), str):
                auth = masked.get(k)
                target_key = k
                break
        if auth and isinstance(auth, str):
            try:
                parts = auth.split()
                if len(parts) == 2:
                    scheme, tok = parts
                    if len(tok) > 12:
                        tok = tok[:6] + "..." + tok[-4:]
                    masked[target_key] = f"{scheme} {tok}"
                else:
                    masked[target_key] = "***masked***"
            except Exception:
                masked[target_key] = "***masked***"
        return masked
    
    def _mask_sensitive_data(self, data: Any) -> Any:
        """
        Recursively mask sensitive information in JSON data.
        Masks: password, access_token, refresh_token, token, secret, api_key, etc.
        """
        if data is None:
            return None
        
        # Sensitive field keywords to mask
        sensitive_keywords = {
            'password', 'passwd', 'pwd', 
            'access_token', 'refresh_token', 'token', 'bearer',
            'secret', 'api_key', 'apikey', 'private_key',
            'client_secret', 'auth_token', 'session_id',
            'jwt', 'authorization'
        }
        
        def _should_mask(key: str) -> bool:
            """Check if field should be masked based on keywords"""
            key_lower = str(key).lower()
            return any(keyword in key_lower for keyword in sensitive_keywords)
        
        def _mask_value(value: str) -> str:
            """Mask a sensitive value, preserving first/last chars for debugging"""
            if not isinstance(value, str) or len(value) == 0:
                return "***masked***"
            if len(value) <= 8:
                return "***masked***"
            # Show first 4 and last 4 chars
            return f"{value[:4]}...{value[-4:]}"
        
        def _mask_recursive(obj: Any) -> Any:
            """Recursively traverse and mask sensitive data"""
            if isinstance(obj, dict):
                masked = {}
                for key, val in obj.items():
                    if _should_mask(key):
                        if isinstance(val, str):
                            masked[key] = _mask_value(val)
                        else:
                            masked[key] = "***masked***"
                    else:
                        masked[key] = _mask_recursive(val)
                return masked
            elif isinstance(obj, list):
                return [_mask_recursive(item) for item in obj]
            else:
                return obj
        
        return _mask_recursive(data)

    def request(self, method: str, path: str, token: Optional[str], params=None, json_body=None, extra_headers: Optional[Dict[str, str]] = None, 
                role: str = None, bac_type: str = None, test_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute HTTP request and save artifact with organized structure.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: API path
            token: Authorization token
            params: Query parameters
            json_body: JSON request body
            extra_headers: Additional headers
            role: User role for organizing artifacts (e.g., 'Admin_HC', 'Employee')
            bac_type: BAC test type - 'horizontal', 'vertical', 'baseline', 'auth'
            test_context: Additional context (self_access, mutation info) for metadata
        """
        # Normalize path defensively: strip BOM and enforce leading slash
        try:
            p = str(path)
        except Exception:
            p = "/"
        # Strip Unicode BOM if present
        p = p.lstrip('\ufeff')
        # Ensure leading slash
        if not p.startswith('/'):
            p = '/' + p
        url = f"{self.base_url}{p}"
        headers = {"Accept": "application/json"}
        # Do not send Authorization only on unauth auth flows (login/register/refresh).
        try:
            if str(bac_type).lower() == 'auth':
                pnorm = str(p).lower().rstrip('/')
                unauth_auth_paths = (
                    '/auth/login',
                    '/auth/signin',
                    '/auth/register',
                    '/auth/signup',
                    '/auth/refresh',
                    '/auth/token',
                )
                if any(pnorm.endswith(x) for x in unauth_auth_paths):
                    token = None
        except Exception:
            pass
        if token:
            # Use configured header and type
            if self.token_type:
                headers[self.token_header] = f"{self.token_type} {token}"
            else:
                headers[self.token_header] = token
        if extra_headers:
            headers.update({k: v for k, v in extra_headers.items() if v is not None})
        attempt = 0
        last_exc = None
        downgraded_localhost_https = False
        while attempt <= self.retries:
            try:
                if self.dry_run:
                    # Simulasi respons saat dry_run
                    resp = {"status_code": 418, "body": {"dry_run": True, "url": url}}
                else:
                    sess = self.session or requests
                    r = sess.request(method.upper(), url, headers=headers, params=params, json=json_body, timeout=self.timeout_s)
                    resp = {"status_code": r.status_code, "body": self._safe_json(r)}
                # Simpan artefak dengan struktur terorganisir
                ts = int(time.time()*1000)
                # Human-friendly UTC time for logs (DD-MM-YYYY HH:MM)
                from datetime import datetime, timezone
                ts_str = datetime.now(timezone.utc).strftime("%d-%m-%Y %H:%M")
                safe = path.strip('/').replace('/','_').replace('?','_').replace('&','_').replace('=','-')
                safe = self._safe_segment(safe, fallback="root", max_len=96)
                status = int(resp.get("status_code") or 0)
                name = f"{ts}_{str(method).upper()}_{safe}_s{status}.json"
                
                # Derive optional target label for deeper categorization (best-practice):
                # - horizontal: same role, to_same_role or to_<role>
                # - vertical: privilege escalation attempts, try to infer target role
                target_label = None
                try:
                    ctx = test_context or {}
                    original_role = (ctx.get("original_role") or role or "").strip()
                    as_role = (ctx.get("as_role") or role or "").strip()
                    mut = ctx.get("mutation") or {}

                    def _norm(s: str) -> str:
                        return (s or "").strip().lower().replace(' ', '_').replace('-', '_')

                    if str(bac_type).lower() == 'horizontal':
                        # same privilege level; target is effectively the same role
                        # Use explicit same-role label for clarity
                        target_label = f"to_{_norm(original_role) or 'same_role'}"
                    elif str(bac_type).lower() == 'vertical':
                        # privilege escalation; if mutation specifies a different role, use it
                        mut_role = mut.get('as_role')
                        if isinstance(mut_role, str) and _norm(mut_role) and _norm(mut_role) != _norm(original_role):
                            target_label = f"to_{_norm(mut_role)}"
                        else:
                            # Infer from path for common admin-ish areas
                            pl = path.lower()
                            adminish = any(k in pl for k in ['/role', '/roles', '/permission', '/permissions', '/users', '/user/', '/rbac', '/admin'])
                            target_label = 'to_admin' if adminish else 'to_unknown'
                except Exception:
                    target_label = None

                # Generate artifact path with role/type/target organization
                artifact_full_path = self._artifact_path(
                    name,
                    role=role,
                    bac_type=bac_type,
                    target_label=target_label,
                    method=str(method).upper(),
                    path=path,
                )
                
                # Mask sensitive data in request/response before saving
                masked_headers = self._mask_headers_for_artifact(headers)
                masked_params = self._mask_sensitive_data(params) if params else None
                masked_json_body = self._mask_sensitive_data(json_body) if json_body else None
                masked_response = self._mask_sensitive_data(resp)
                
                # Build artifact metadata
                artifact_data = {
                    "request": {
                        "method": method, 
                        "url": url, 
                        "headers": masked_headers, 
                        "params": masked_params, 
                        "json": masked_json_body
                    },
                    "response": masked_response,
                    "metadata": {
                        "role": role,
                        "bac_type": bac_type,
                        "timestamp": ts,
                        "timestamp_str": ts_str,
                        # Convenience combined label (e.g., "employee (BOLA)") for human scanning
                        "folder_label": f"{(role or '').strip().lower().replace(' ','_').replace('-','_')} (" + ("IDOR" if str(bac_type).lower()=="horizontal" else "BOLA" if str(bac_type).lower()=="vertical" else "AUTH" if str(bac_type).lower()=="auth" else "BASELINE") + ")",
                        "artifact_path": artifact_full_path,
                        "test_context": test_context or {}
                    }
                }
                
                with open(artifact_full_path, "w", encoding="utf-8") as f:
                    json.dump(artifact_data, f, indent=2)
                
                resp["artifact"] = artifact_full_path
                return resp
            except Exception as e:
                # Common local-dev mismatch: HTTPS sent to HTTP-only dev server.
                # If it happens on localhost/127.0.0.1, downgrade once and retry.
                try:
                    emsg = str(e)
                    parsed = urlsplit(url)
                    host = (parsed.hostname or "").lower()
                    is_local = host in ("127.0.0.1", "localhost")
                    is_https = (parsed.scheme or "").lower() == "https"
                    if (
                        not downgraded_localhost_https
                        and is_local
                        and is_https
                        and ("WRONG_VERSION_NUMBER" in emsg or "SSLError" in emsg)
                    ):
                        url = url.replace("https://", "http://", 1)
                        if isinstance(self.base_url, str):
                            self.base_url = self.base_url.replace("https://", "http://", 1)
                        downgraded_localhost_https = True
                        continue
                except Exception:
                    pass
                last_exc = e
                attempt += 1
                # Exponential backoff with jitter
                delay = min(0.25 * (2 ** attempt), 2.0) + random.random() * 0.2
                time.sleep(delay)
        raise last_exc

    def smart_request(self, method: str, path: str, token: Optional[str], openapi: Dict[str, Any], 
                      params=None, json_body=None, discovered_ids: Dict[str, Any] = None,
                      extra_headers: Optional[Dict[str, str]] = None, role: str = None, 
                      bac_type: str = None, test_context: Dict[str, Any] = None, max_retries: int = 2) -> Dict[str, Any]:
        """
        Smart HTTP request with automatic payload generation and adaptive retry on 400 errors.
        
        This method:
        1. If json_body is None and method requires body (POST/PUT/PATCH), auto-generate from OpenAPI schema
        2. Execute request normally
        3. If 400 error, analyze response and retry with adjusted payload
        4. Return final response with metadata about payload generation
        
        Args:
            method: HTTP method
            path: API path
            token: Auth token
            openapi: OpenAPI specification dict
            params: Query parameters (optional)
            json_body: Request body (if None, will auto-generate for POST/PUT/PATCH)
            discovered_ids: Dict of discovered resource IDs for payload generation
            extra_headers: Additional headers
            role: User role
            bac_type: BAC test type
            test_context: Test context metadata
            max_retries: Max retry attempts for 400 errors (default: 2)
        
        Returns:
            Response dict with additional 'payload_info' metadata
        """
        from ai_agent.core.utils import extract_request_schema, generate_payload_from_schema
        
        # Flag to track if we generated the payload
        payload_generated = False
        original_body = json_body
        schema_info = None
        
        # Special handling for /auth/login - inject real credentials from .env
        if path.rstrip('/').endswith('/auth/login') and method.upper() == 'POST':
            if role:
                username, password = self._role_credentials_from_env(role)
                if username and password:
                    # Inject credentials with field names that match schema when possible.
                    if json_body is None:
                        json_body = {}
                    if isinstance(json_body, dict):
                        # Inspect schema to decide whether backend expects username or email.
                        login_schema = extract_request_schema(openapi, method, path) or {}
                        required = set(login_schema.get('required') or [])
                        props = set((login_schema.get('properties') or {}).keys())
                        want_email = ('email' in required) or ('email' in props and 'username' not in required)
                        want_username = ('username' in required) or ('username' in props and 'email' not in required)
                        if want_username:
                            json_body['username'] = username
                        if want_email:
                            json_body['email'] = username
                        # Fallback: set both if schema is unclear.
                        if not want_username and not want_email:
                            json_body['username'] = username
                            json_body['email'] = username
                        json_body['password'] = password
                        payload_generated = True
                        print(f"[AUTH] Injected credentials for role {role}: {username}")
        
        # Endpoints that should skip smart payload generation
        skip_endpoints = ['/auth/login', '/auth/register', '/auth/refresh', '/auth/logout']
        should_skip = any(path.rstrip('/').endswith(endpoint.rstrip('/')) for endpoint in skip_endpoints)
        
        # DEBUG: Check conditions
        # Auto-generate payload for methods that typically require body (but skip auth endpoints)
        if json_body is None and method.upper() in ('POST', 'PUT', 'PATCH') and not should_skip:
            schema_info = extract_request_schema(openapi, method, path)
            
            # extract_request_schema returns wrapper with 'schema' key for the actual schema
            actual_schema = schema_info.get('schema', schema_info) if isinstance(schema_info, dict) else {}
            has_content = bool(actual_schema and (actual_schema.get('properties') or actual_schema.get('items') or actual_schema.get('type')))
            
            # Generate payload if we have usable schema
            if has_content:
                # Pass actual schema to generator, not the wrapper
                json_body = generate_payload_from_schema(actual_schema, discovered_ids)
                payload_generated = True
                # Only print compact message
                schema_type = actual_schema.get('type', 'object')
                print(f"      [SMART] Auto-generated {schema_type} payload")
        
        # Try initial request
        attempt = 0
        last_response = None
        self_access = bool((test_context or {}).get("self_access", True))
        
        while attempt <= max_retries:
            try:
                # Final ID normalization before sending request:
                # prefer discovered IDs over synthetic defaults for *_id fields.
                if isinstance(json_body, dict) and isinstance(discovered_ids, dict) and discovered_ids:
                    for fk, fv in list(json_body.items()):
                        if not isinstance(fk, str):
                            continue
                        if "id" not in fk.lower():
                            continue
                        fkl = fk.lower()
                        # For user_id-like fields, always use discovered user candidate (self/other).
                        if "user" in fkl:
                            uid = self._pick_user_id(discovered_ids, self_access=self_access)
                            if isinstance(uid, int) and uid > 0 and fv != uid:
                                json_body[fk] = uid
                            continue
                        rid = self._resolve_discovered_id_for_field(fk, discovered_ids)
                        if isinstance(rid, int) and rid > 0:
                            # Replace missing/synthetic values with discovered resource IDs.
                            if fv is None or (isinstance(fv, int) and fv <= 1):
                                json_body[fk] = rid
                # Payroll uniqueness guard:
                # avoid duplicate (user_id, month, year) combinations before POST /payroll.
                if isinstance(json_body, dict):
                    self._ensure_payroll_unique_period(
                        method=method,
                        path=path,
                        json_body=json_body,
                        token=token,
                        role=role,
                        bac_type=bac_type,
                        test_context=test_context,
                        attempt=attempt,
                    )

                response = self.request(
                    method=method,
                    path=path,
                    token=token,
                    params=params,
                    json_body=json_body,
                    extra_headers=extra_headers,
                    role=role,
                    bac_type=bac_type,
                    test_context=test_context
                )
                
                last_response = response
                status_code = response.get('status_code', 0)
                err_text = self._error_text_from_response(response)
                
                # Success or non-400 error - return immediately
                if status_code != 400:
                    # Retry once with rotated period on known payroll unique conflict.
                    if (
                        attempt < max_retries
                        and self._is_payroll_unique_conflict(method, path, status_code, err_text)
                        and isinstance(json_body, dict)
                    ):
                        self._bump_payroll_period(json_body, step=max(1, attempt + 1))
                        attempt += 1
                        continue
                    response['payload_info'] = {
                        'auto_generated': payload_generated,
                        'original_body': original_body,
                        'final_body': json_body,
                        'attempts': attempt + 1,
                        'schema_available': bool(schema_info) if payload_generated else None
                    }
                    return response
                
                # Got 400 - try to improve payload if we haven't exhausted retries
                if attempt < max_retries:
                    # Analyze error message
                    error_body = response.get('body', {})
                    error_msg = str(error_body.get('message') or error_body.get('detail') or '').lower()
                    
                    # Try to extract missing field from error message
                    missing_field = self._extract_missing_field(error_msg)
                    
                    # Also extract required fields when API returns {"field": ["...required..."]}
                    required_fields = self._extract_required_fields_from_body(error_body)
                    if required_fields and isinstance(json_body, dict):
                        changed = False
                        for rf in required_fields:
                            if rf in json_body:
                                continue
                            rfl = rf.lower()
                            schema_props = {}
                            if isinstance(schema_info, dict):
                                schema_props = schema_info.get('properties') or {}
                            # Try live API discovery first (best effort), then schema defaults.
                            discovered_val = self._discover_field_value_via_api(
                                field_name=rf,
                                token=token,
                                role=role,
                                bac_type=bac_type,
                                test_context=test_context,
                            )
                            if discovered_val is not None:
                                json_body[rf] = discovered_val
                                changed = True
                                continue
                            json_body[rf] = self._default_for_required_field(
                                rf,
                                schema_props.get(rf) or {},
                                discovered_ids=discovered_ids,
                                self_access=self_access,
                            )
                            changed = True
                        if changed:
                            attempt += 1
                            continue

                    if missing_field and isinstance(json_body, dict):
                        # Add the missing field with a default value
                        if missing_field not in json_body:
                            # Try to infer type from field name
                            missing_l = missing_field.lower()
                            if 'id' in missing_l:
                                if "user" in missing_l:
                                    rid = self._pick_user_id(discovered_ids or {}, self_access=self_access)
                                else:
                                    rid = self._resolve_discovered_id_for_field(missing_field, discovered_ids or {})
                                json_body[missing_field] = rid if isinstance(rid, int) and rid > 0 else 1
                            elif (live_val := self._discover_field_value_via_api(
                                field_name=missing_field,
                                token=token,
                                role=role,
                                bac_type=bac_type,
                                test_context=test_context,
                            )) is not None:
                                json_body[missing_field] = live_val
                            elif 'email' in missing_field.lower():
                                json_body[missing_field] = "test@example.com"
                            elif 'name' in missing_field.lower():
                                json_body[missing_field] = "Test Name"
                            elif 'status' in missing_field.lower():
                                json_body[missing_field] = "active"
                            else:
                                json_body[missing_field] = "default_value"
                            
                            # Retry with updated payload
                            attempt += 1
                            continue
                
                # If we reach here, either exhausted retries or couldn't fix the issue
                break
                
            except Exception as e:
                # Network or other errors - don't retry, raise immediately
                raise e
        
        # Return last response with metadata
        if last_response:
            last_response['payload_info'] = {
                'auto_generated': payload_generated,
                'original_body': original_body,
                'final_body': json_body,
                'attempts': attempt + 1,
                'schema_available': bool(extract_request_schema(openapi, method, path)) if payload_generated else None,
                'failed_after_retries': True
            }
        
        return last_response or {'status_code': 0, 'body': {}, 'error': 'No response received'}
    
    @staticmethod
    def _env_key_base(role_name: str) -> str:
        s = str(role_name or "").strip().upper()
        s = "".join(ch if ch.isalnum() else "_" for ch in s)
        while "__" in s:
            s = s.replace("__", "_")
        return s.strip("_")

    @classmethod
    def _role_credentials_from_env(cls, role_name: str) -> tuple[Optional[str], Optional[str]]:
        """
        Resolve role credentials without hardcoded role names.
        Supports:
        - <ROLE>_USERNAME + <ROLE>_PASSWORD
        - <ROLE>_EMAIL + <ROLE>_PASSWORD
        """
        base = cls._env_key_base(role_name)
        if not base:
            return None, None
        username = os.getenv(f"{base}_USERNAME")
        email = os.getenv(f"{base}_EMAIL")
        password = os.getenv(f"{base}_PASSWORD")
        identity = username or email
        return identity, password

    @staticmethod
    def _default_for_required_field(
        field_name: str,
        field_schema: Dict[str, Any],
        discovered_ids: Dict[str, Any] = None,
        self_access: bool = True,
    ) -> Any:
        """
        Generate deterministic default from schema first, then field semantics.
        Avoid role- or project-specific hardcoded values.
        """
        import datetime as _dt
        discovered_ids = discovered_ids or {}

        ftype = str(field_schema.get("type") or "").lower()
        fmt = str(field_schema.get("format") or "").lower()
        name = str(field_name or "").lower()

        # For ID-like fields, prioritize discovered IDs over schema examples/defaults.
        if "id" in name:
            if "user" in name:
                uid = HttpClient._pick_user_id(discovered_ids, self_access=self_access)
                if isinstance(uid, int) and uid > 0:
                    return uid
            rid = HttpClient._resolve_discovered_id_for_field(field_name, discovered_ids)
            if isinstance(rid, int) and rid > 0:
                return rid

        enum_vals = field_schema.get("enum")
        if isinstance(enum_vals, list) and enum_vals:
            return enum_vals[0]
        if field_schema.get("example") is not None:
            return field_schema.get("example")
        if field_schema.get("default") is not None:
            return field_schema.get("default")

        if ftype in ("integer", "number") or "id" in name:
            minimum = field_schema.get("minimum")
            if isinstance(minimum, (int, float)):
                return int(minimum)
            if "year" in name:
                return _dt.date.today().year
            if "month" in name:
                return 1
            return 1
        if ftype == "boolean":
            return False
        if fmt == "email" or "email" in name:
            return "test@example.com"
        if fmt in ("date-time", "datetime"):
            return _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        if fmt == "date" or "date" in name:
            return _dt.date.today().isoformat()
        if "password" in name:
            return "Test123!Secure"
        if "username" in name:
            return "tester_auto"
        if "name" in name:
            return "Test Name"
        if "salary" in name:
            return 1000
        if ftype == "array":
            return []
        if ftype == "object":
            return {}
        return "default_value"

    @staticmethod
    def _pick_user_id(discovered_ids: Dict[str, Any], self_access: bool = True) -> Optional[int]:
        """
        Pick best user id from discovered IDs.
        - self_access=True  -> prefer user_id/user
        - self_access=False -> prefer other_user_id/other_user, fallback to user_id
        """
        try:
            if not isinstance(discovered_ids, dict):
                return None
            if not self_access:
                for k in ("other_user_id", "other_user"):
                    v = discovered_ids.get(k)
                    if isinstance(v, int) and v > 0:
                        return v
            for k in ("user_id", "id_user", "user"):
                v = discovered_ids.get(k)
                if isinstance(v, int) and v > 0:
                    return v
        except Exception:
            return None
        return None
    
    @staticmethod
    def _extract_list_items(body: Any) -> list[dict]:
        """Extract list items from common API response envelopes."""
        try:
            if isinstance(body, list):
                return [x for x in body if isinstance(x, dict)]
            if not isinstance(body, dict):
                return []
            candidates = [
                ["data", "items"],
                ["data", "results"],
                ["data", "list"],
                ["items"],
                ["results"],
                ["list"],
                ["data"],
            ]
            for keys in candidates:
                cur = body
                ok = True
                for k in keys:
                    if isinstance(cur, dict) and k in cur:
                        cur = cur[k]
                    else:
                        ok = False
                        break
                if ok and isinstance(cur, list):
                    return [x for x in cur if isinstance(x, dict)]
            return []
        except Exception:
            return []

    def _discover_field_value_via_api(
        self,
        field_name: str,
        token: Optional[str],
        role: Optional[str],
        bac_type: Optional[str],
        test_context: Optional[Dict[str, Any]],
    ) -> Any:
        """
        Discover a plausible field value by calling list endpoints.
        Example: role_name -> GET /roles, user_id -> GET /users.
        """
        try:
            f = str(field_name or "").strip().lower()
            if not f:
                return None
            cache_key = f
            if cache_key in self._value_probe_cache:
                return self._value_probe_cache.get(cache_key)

            endpoint_candidates: list[str] = []
            if "user" in f or f in ("id_user", "user_id"):
                endpoint_candidates.extend(["/users", "/user"])
            if "role" in f:
                endpoint_candidates.extend(["/roles", "/role"])
            if "permission" in f:
                endpoint_candidates.extend(["/permissions", "/permission"])
            if "employee" in f:
                endpoint_candidates.extend(["/employees", "/employee", "/users"])
            if "department" in f:
                endpoint_candidates.extend(["/departments", "/department"])

            # Deduplicate while preserving order.
            seen = set()
            endpoint_candidates = [p for p in endpoint_candidates if not (p in seen or seen.add(p))]
            if not endpoint_candidates:
                return None

            for ep in endpoint_candidates:
                try:
                    resp = self.request(
                        method="GET",
                        path=ep,
                        token=token,
                        params=None,
                        json_body=None,
                        extra_headers=None,
                        role=role,
                        bac_type=bac_type or "discovery",
                        test_context=test_context or {},
                    )
                    if int(resp.get("status_code") or 0) // 100 != 2:
                        continue
                    items = self._extract_list_items(resp.get("body"))
                    if not items:
                        continue
                    first = items[0]
                    if not isinstance(first, dict):
                        continue

                    # ID fields
                    if "id" in f:
                        for k in ("id", "user_id", "id_user", "role_id", "permission_id"):
                            v = first.get(k)
                            if isinstance(v, int) and v > 0:
                                self._value_probe_cache[cache_key] = v
                                return v
                        for k, v in first.items():
                            if isinstance(k, str) and "id" in k.lower() and isinstance(v, int) and v > 0:
                                self._value_probe_cache[cache_key] = v
                                return v

                    # Name/code fields
                    if "name" in f or "code" in f or "role" in f or "permission" in f:
                        for k in ("name", "role_name", "permission_name", "code", "slug", "title"):
                            v = first.get(k)
                            if isinstance(v, str) and v.strip():
                                self._value_probe_cache[cache_key] = v.strip()
                                return v.strip()
                except Exception:
                    continue
        except Exception:
            return None
        return None

    @staticmethod
    def _error_text_from_response(response: Dict[str, Any]) -> str:
        try:
            body = (response or {}).get("body", {})
            if isinstance(body, dict):
                parts = []
                for k in ("message", "detail", "error", "text"):
                    v = body.get(k)
                    if isinstance(v, str):
                        parts.append(v)
                if parts:
                    return " | ".join(parts).lower()
                return str(body).lower()
            return str(body).lower()
        except Exception:
            return ""

    @staticmethod
    def _is_payroll_unique_conflict(method: str, path: str, status_code: int, err_text: str) -> bool:
        try:
            if str(method or "").upper() != "POST":
                return False
            p = str(path or "").lower().rstrip("/")
            if not p.endswith("/payroll"):
                return False
            text = str(err_text or "").lower()
            if "unique constraint failed" in text and "payrolls.user_id" in text:
                return True
            if status_code in (409, 422) and ("unique" in text or "already exists" in text or "duplicate" in text):
                return True
            # Some backends return 500 for uncaught IntegrityError.
            if status_code >= 500 and ("integrityerror" in text or "unique" in text):
                return True
            return False
        except Exception:
            return False

    def _ensure_payroll_unique_period(
        self,
        method: str,
        path: str,
        json_body: Dict[str, Any],
        token: Optional[str],
        role: Optional[str],
        bac_type: Optional[str],
        test_context: Optional[Dict[str, Any]],
        attempt: int = 0,
    ) -> None:
        """
        Ensure POST /payroll has a non-colliding (month, year) for the selected user_id.
        """
        try:
            if str(method or "").upper() != "POST":
                return
            p = str(path or "").lower().rstrip("/")
            if not p.endswith("/payroll"):
                return
            user_id = json_body.get("user_id")
            if not isinstance(user_id, int) or user_id <= 0:
                return

            existing = self._fetch_existing_payroll_periods(
                user_id=user_id,
                token=token,
                role=role,
                bac_type=bac_type,
                test_context=test_context,
            )
            if not existing:
                return

            # Normalize month/year defaults if absent.
            month = json_body.get("month")
            year = json_body.get("year")
            import datetime as _dt
            today = _dt.date.today()
            if not isinstance(month, int) or not (1 <= month <= 12):
                month = today.month
            if not isinstance(year, int) or year < 2000:
                year = today.year

            # Rotate candidate to avoid existing tuples.
            cand_month = month
            cand_year = year
            for shift in range(attempt, attempt + 48):
                m = ((cand_month - 1 + shift) % 12) + 1
                y = cand_year + ((cand_month - 1 + shift) // 12)
                if (m, y) not in existing:
                    json_body["month"] = m
                    json_body["year"] = y
                    return
        except Exception:
            return

    def _fetch_existing_payroll_periods(
        self,
        user_id: int,
        token: Optional[str],
        role: Optional[str],
        bac_type: Optional[str],
        test_context: Optional[Dict[str, Any]],
    ) -> set[tuple[int, int]]:
        """
        Read existing payroll tuples for a user from GET /payroll list endpoint.
        """
        cache_key = f"payroll_periods_user_{int(user_id)}"
        cached = self._value_probe_cache.get(cache_key)
        if isinstance(cached, set):
            return cached
        out: set[tuple[int, int]] = set()
        try:
            resp = self.request(
                method="GET",
                path="/payroll",
                token=token,
                params=None,
                json_body=None,
                extra_headers=None,
                role=role,
                bac_type=bac_type or "discovery",
                test_context=test_context or {},
            )
            if int(resp.get("status_code") or 0) // 100 != 2:
                self._value_probe_cache[cache_key] = out
                return out
            items = self._extract_list_items(resp.get("body"))
            for it in items:
                if not isinstance(it, dict):
                    continue
                uid = it.get("user_id")
                # Some APIs nest user object.
                if uid is None and isinstance(it.get("user"), dict):
                    uid = it.get("user", {}).get("id")
                try:
                    uid_i = int(uid)
                except Exception:
                    continue
                if uid_i != int(user_id):
                    continue
                try:
                    m = int(it.get("month"))
                    y = int(it.get("year"))
                    if 1 <= m <= 12 and y >= 2000:
                        out.add((m, y))
                except Exception:
                    continue
        except Exception:
            pass
        self._value_probe_cache[cache_key] = out
        return out

    @staticmethod
    def _bump_payroll_period(json_body: Dict[str, Any], step: int = 1) -> None:
        try:
            import datetime as _dt
            month = json_body.get("month")
            year = json_body.get("year")
            today = _dt.date.today()
            if not isinstance(month, int) or not (1 <= month <= 12):
                month = today.month
            if not isinstance(year, int) or year < 2000:
                year = today.year
            idx = (month - 1) + max(1, int(step))
            json_body["month"] = (idx % 12) + 1
            json_body["year"] = year + (idx // 12)
        except Exception:
            return

    @staticmethod
    def _resolve_discovered_id_for_field(field_name: str, discovered_ids: Dict[str, Any]) -> Optional[int]:
        """
        Resolve best discovered ID for an id-like field (e.g., user_id, id_user, payroll_id).
        """
        try:
            if not isinstance(discovered_ids, dict):
                return None
            fname = str(field_name or "").lower().strip()
            if not fname or "id" not in fname:
                return None

            # 1) Exact/alias matches first.
            aliases = [fname]
            if fname.startswith("id_"):
                aliases.append(fname[3:])
            if fname.endswith("_id"):
                aliases.append(fname[:-3])
            aliases.extend(["user_id", "id_user", "user"])
            for a in aliases:
                v = discovered_ids.get(a)
                if isinstance(v, int) and v > 0:
                    return v

            # 2) Token-based matching.
            token = fname.replace("id_", "").replace("_id", "")
            for k, v in discovered_ids.items():
                if not isinstance(k, str):
                    continue
                if not (isinstance(v, int) and v > 0):
                    continue
                kl = k.lower()
                if token and (token in kl or kl in token):
                    return v

            # 3) Fallback to first positive int ID-like key.
            for k, v in discovered_ids.items():
                if isinstance(k, str) and "id" in k.lower() and isinstance(v, int) and v > 0:
                    return v
        except Exception:
            return None
        return None
    
    @staticmethod
    def _extract_required_fields_from_body(error_body: Any) -> list[str]:
        """
        Extract required field names from structured 400 payloads, e.g.
        {"username": ["This field is required."], "password": ["This field is required."]}
        """
        try:
            out = []
            if isinstance(error_body, dict):
                for k, v in error_body.items():
                    if not isinstance(k, str):
                        continue
                    if isinstance(v, list):
                        joined = " ".join(str(x) for x in v).lower()
                        if "required" in joined:
                            out.append(k)
                    elif isinstance(v, str):
                        if "required" in v.lower():
                            out.append(k)
            return out
        except Exception:
            return []
    
    @staticmethod
    def _extract_missing_field(error_message: str) -> Optional[str]:
        """
        Extract missing field name from common error message patterns.
        
        Examples:
        - "field 'email' is required" -> "email"
        - "Missing required parameter: name" -> "name"
        - "The field status is required." -> "status"
        """
        import re
        
        # Pattern 1: field 'xxx' is required
        match = re.search(r"field\s+['\"]([^'\"]+)['\"].*required", error_message, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Pattern 2: Missing required parameter: xxx
        match = re.search(r"missing.*required.*parameter[:\s]+([a-z_]+)", error_message, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Pattern 3: field xxx is required
        match = re.search(r"field\s+([a-z_]+).*required", error_message, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Pattern 4: xxx is required
        match = re.search(r"([a-z_]+)\s+is\s+required", error_message, re.IGNORECASE)
        if match:
            field = match.group(1)
            # Avoid false positives like "authentication is required"
            if field not in ['authentication', 'authorization', 'permission', 'access']:
                return field
        
        return None

    @staticmethod
    def _safe_json(r):
        try:
            return r.json()
        except Exception:
            return {"text": r.text[:2000]}
