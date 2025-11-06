import os, time, json, pathlib, requests, random
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
        pathlib.Path(artifacts_dir).mkdir(parents=True, exist_ok=True)
        self.session = None if dry_run else requests.Session()

    def _artifact_path(self, name: str, role: str = None, bac_type: str = None, target_label: str | None = None) -> str:
        """
        Generate organized artifact path structure:
        artifacts/
          {role}/
            horizontal/  (IDOR - same privilege level, different user)
            vertical/    (BOLA - privilege escalation)
            baseline/    (normal expected operations)
            auth/        (authentication related)
        """
        if role:
            # Normalize role name for folder (lowercase, replace spaces/special chars)
            role_folder = role.lower().replace(' ', '_').replace('-', '_')
            
            # Determine subfolder based on BAC type, mapped to expected labels
            bt = (bac_type or "baseline").strip().lower()
            label = (
                "IDOR" if bt == "horizontal" else
                "BOLA" if bt == "vertical" else
                "AUTH" if bt == "auth" else
                "BASELINE"
            )
            
            # Optional target label (e.g., to_admin, to_employee, to_same_role)
            parts = [self.artifacts_dir, role_folder, label]
            if target_label:
                safe_target = str(target_label).lower().strip()
                safe_target = safe_target.replace(' ', '_').replace('-', '_')
                parts.append(safe_target)

            # Create directory structure
            full_dir = os.path.join(*parts)
            pathlib.Path(full_dir).mkdir(parents=True, exist_ok=True)
            return os.path.join(full_dir, name)
        else:
            # Fallback to flat structure if no role provided
            return os.path.join(self.artifacts_dir, name)

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
                name = f"{ts}_{method}_{safe}.json"
                
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
                artifact_full_path = self._artifact_path(name, role=role, bac_type=bac_type, target_label=target_label)
                
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
                        "test_context": test_context or {}
                    }
                }
                
                with open(artifact_full_path, "w", encoding="utf-8") as f:
                    json.dump(artifact_data, f, indent=2)
                
                resp["artifact"] = artifact_full_path
                return resp
            except Exception as e:
                last_exc = e
                attempt += 1
                # Exponential backoff with jitter
                delay = min(0.25 * (2 ** attempt), 2.0) + random.random() * 0.2
                time.sleep(delay)
        raise last_exc

    @staticmethod
    def _safe_json(r):
        try:
            return r.json()
        except Exception:
            return {"text": r.text[:2000]}
