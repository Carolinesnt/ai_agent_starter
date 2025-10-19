import json
from typing import Dict, Any, Optional
import os
from .tools_http import HttpClient

class AuthManager:
    def __init__(self, http: HttpClient, auth_cfg: Dict[str, Any], openapi: Optional[Dict[str, Any]] = None):
        self.http = http
        self.cache = {}  # role -> token
        self._global = auth_cfg or {}
        token_cfg = (auth_cfg or {}).get("token", {}) if isinstance(auth_cfg, dict) else {}
        self.token_json_path_default = token_cfg.get("token_json_path") or "token.access_token"
        self.openapi = openapi or {}
        # Global credential field names override (e.g., email/password)
        self.global_user_field = (self._global.get("user_field") or self._global.get("credentials_field") or {}).get("username") if isinstance(self._global.get("credentials_field"), dict) else (self._global.get("user_field") or "username")
        self.global_pass_field = (self._global.get("credentials_field", {}) or {}).get("password") if isinstance(self._global.get("credentials_field"), dict) else "password"
        # Support two formats:
        # 1) roles: [ {name, flow, endpoint, payload{username,password,user_id}, token_json_path} ]
        # 2) roles: { RoleName: { login_endpoint, credentials{username,password} } }
        roles_cfg = auth_cfg.get("roles", {})
        parsed = {}
        if isinstance(roles_cfg, list):
            for r in roles_cfg:
                parsed[r.get("name")] = r
        elif isinstance(roles_cfg, dict):
            for name, val in roles_cfg.items():
                if not isinstance(val, dict):
                    continue
                parsed[name] = {
                    "name": name,
                    "flow": val.get("flow", "password"),
                    "endpoint": val.get("login_endpoint") or val.get("endpoint", "/auth/login"),
                    "payload": {
                        # Support both username or email in credentials
                        "username": (val.get("credentials") or {}).get("username") or (val.get("credentials") or {}).get("email"),
                        "password": (val.get("credentials") or {}).get("password"),
                        # Best-effort synthetic user_id if not provided
                        "user_id": self._default_user_id(name),
                    },
                    # Try typical paths if not specified
                    "token_json_path": val.get("token_json_path") or "token.access_token",
                    # Preferred user field name for this role (username/email)
                    "user_field": val.get("user_field") or self._global.get("user_field") or None,
                }
        else:
            parsed = {}
        self.roles = parsed

    def get_token(self, role: str) -> str:
        if role in self.cache:
            return self.cache[role]
        info = self.roles.get(role)
        if not info:
            raise ValueError(f"Unknown role: {role}")
        # In dry_run, skip real login
        if getattr(self.http, "dry_run", False):
            token = f"dry_token_{role}"
            self.cache[role] = token
            return token
        if info.get("flow") == "static_token":
            token = info["token"]
        else:
            ep = info.get("endpoint") or "/auth/login"
            payload = dict(info.get("payload", {}) or {})
            # Always prefer environment variables if provided
            env_user, env_pass = self._env_credentials_for_role(role)
            env_email = self._env_email_for_role(role)
            # Determine which user field name to use
            user_field = info.get("user_field") or self._infer_user_field_from_openapi(info.get("endpoint")) or self.global_user_field or "username"
            pass_field = self._infer_pass_field_from_openapi(info.get("endpoint")) or self.global_pass_field or "password"
            # Determine user value (prefer email if provided)
            user_value = env_email or env_user or payload.get("username") or payload.get("email")
            if user_value is not None:
                payload[user_field] = user_value
            # Ensure we don't send both username and email
            for k in ("username", "email"):
                if k != user_field and k in payload:
                    payload.pop(k, None)
            if env_pass:
                payload[pass_field] = env_pass
            # Do not include user_id in login payload unless explicitly requested
            include_uid = bool(self._global.get("include_user_id_in_login") or info.get("include_user_id_in_login"))
            if not include_uid and "user_id" in payload:
                payload.pop("user_id", None)
            resp = self.http.request("POST", ep, token=None, json_body=payload)
            token = (
                self._extract(resp.get("body", {}), info.get("token_json_path") or self.token_json_path_default)
                or self._extract(resp.get("body", {}), "access_token")
                or self._extract(resp.get("body", {}), "data.access_token")
            )
        self.cache[role] = token
        return token

    def get_user_id(self, role: str) -> int:
        # Prefer explicit env override
        env_uid = self._env_user_id_for_role(role)
        if isinstance(env_uid, int) and env_uid > 0:
            return env_uid
        info = self.roles.get(role, {})
        uid = info.get("payload", {}).get("user_id")
        if isinstance(uid, int):
            return uid
        # Derive a deterministic synthetic ID if not provided
        return self._default_user_id(role)

    @staticmethod
    def _extract(obj: Dict[str, Any], path: Optional[str]):
        if not path:
            return None
        cur = obj
        for key in path.split("."):
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                return None
        return cur

    @staticmethod
    def _default_user_id(role: str) -> int:
        # Simple mapping to keep self vs other scenarios stable in dry-run
        if role.lower().startswith("admin"):
            return 1
        if role.lower().startswith("employee_2"):
            return 102
        if role.lower().startswith("employee"):
            return 101
        return 0

    @staticmethod
    def _env_key_base(role: str) -> str:
        # Map role name to ENV prefix, e.g., Admin_HC -> ADMIN_HC, Employee -> EMPLOYEE, Employee_2 -> EMPLOYEE_2
        return ''.join([c if c.isalnum() else '_' for c in role]).upper()

    def _env_credentials_for_role(self, role: str):
        base = self._env_key_base(role)
        # Common fallbacks for well-known roles
        fallback_map = {
            "ADMIN_HC": ("ADMIN_USERNAME", "ADMIN_PASSWORD"),
            "EMPLOYEE": ("EMPLOYEE_USERNAME", "EMPLOYEE_PASSWORD"),
        }
        user_key = f"{base}_USERNAME"
        pass_key = f"{base}_PASSWORD"
        # If base maps to a known alias, use those too as fallback
        aliases = fallback_map.get(base)
        cand_users = [user_key]
        cand_pass = [pass_key]
        if aliases:
            cand_users.insert(0, aliases[0])
            cand_pass.insert(0, aliases[1])
        env_user = None
        env_pass = None
        for k in cand_users:
            if os.getenv(k):
                env_user = os.getenv(k)
                break
        for k in cand_pass:
            if os.getenv(k):
                env_pass = os.getenv(k)
                break
        return env_user, env_pass

    def _env_user_id_for_role(self, role: str):
        base = self._env_key_base(role)
        val = os.getenv(f"{base}_USER_ID")
        if not val:
            return None
        try:
            return int(val)
        except Exception:
            return None

    def _env_email_for_role(self, role: str) -> Optional[str]:
        base = self._env_key_base(role)
        # Prefer ROLE_EMAIL; fall back to well-known aliases
        candidates = [f"{base}_EMAIL"]
        alias_map = {
            "ADMIN_HC": "ADMIN_EMAIL",
            "EMPLOYEE": "EMPLOYEE_EMAIL",
            "EMPLOYEE_2": "EMPLOYEE_2_EMAIL",
        }
        if base in alias_map:
            candidates.insert(0, alias_map[base])
        for k in candidates:
            v = os.getenv(k)
            if v:
                return v
        return None

    # --- OpenAPI helpers ---
    def _openapi_schema_for(self, path: Optional[str], method: str = "post") -> Optional[Dict[str, Any]]:
        try:
            p = str(path or "").strip()
            if not p:
                return None
            if not p.startswith('/'):
                p = '/' + p
            paths = (self.openapi or {}).get('paths', {})
            if p not in paths:
                return None
            node = paths[p].get(method.lower()) or paths[p].get(method.upper())
            if not node:
                return None
            rb = (node.get('requestBody') or {}).get('content', {})
            app = rb.get('application/json') or rb.get('application/x-www-form-urlencoded') or {}
            schema = app.get('schema') or {}
            return schema
        except Exception:
            return None

    def _infer_user_field_from_openapi(self, path: Optional[str]) -> Optional[str]:
        schema = self._openapi_schema_for(path, 'post')
        if not schema:
            return None
        props = (schema.get('properties') or {}) if isinstance(schema, dict) else {}
        keys = set(props.keys())
        # Prefer email over username
        for cand in ['email', 'user_email', 'login', 'username']:
            if cand in keys:
                return cand
        # Try case-insensitive
        low = {k.lower(): k for k in keys}
        for cand in ['email', 'user_email', 'login', 'username']:
            if cand in low:
                return low[cand]
        return None

    def _infer_pass_field_from_openapi(self, path: Optional[str]) -> Optional[str]:
        schema = self._openapi_schema_for(path, 'post')
        if not schema:
            return None
        props = (schema.get('properties') or {}) if isinstance(schema, dict) else {}
        keys = set(props.keys())
        for cand in ['password', 'pass', 'pwd']:
            if cand in keys:
                return cand
        low = {k.lower(): k for k in keys}
        for cand in ['password', 'pass', 'pwd']:
            if cand in low:
                return low[cand]
        return None
