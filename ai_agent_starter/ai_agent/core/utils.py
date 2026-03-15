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
    s = str(path or "").strip()
    # Ensure leading slash
    if not s.startswith('/'):
        s = '/' + s
    # Collapse duplicate slashes
    s = re.sub(r"//+", "/", s)
    return s

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
    """Load canonical policy from YAML only."""
    ypath = os.path.join(config_dir, "policy.yaml")
    if os.path.exists(ypath):
        return load_yaml(ypath)
    raise FileNotFoundError(f"No policy file found in {config_dir} (required: policy.yaml)")

def endpoints_from_policy(policy: Dict[str, Any]) -> List[dict]:
    """Collect unique METHOD:/path from rbac_rules (allowed_endpoints + critical_deny) across roles."""
    out = []
    seen = set()
    try:
        rules = (policy or {}).get('rbac_rules', {}) or {}
        for _role, r in rules.items():
            for key in (r.get('allowed_endpoints') or []) + (r.get('critical_deny') or []):
                if not isinstance(key, str) or ':' not in key:
                    continue
                mth, pth = key.split(':', 1)
                m = mth.strip().upper()
                p = normalize_path(pth.strip())
                k = (m, p)
                if k in seen:
                    continue
                seen.add(k)
                out.append({"method": m, "path": p})
    except Exception:
        return []
    return out

def load_endpoints_config(config_dir: str) -> List[dict]:
    """Load endpoints from config/endpoints.yaml if present.
    Accepts:
      - endpoints: ["GET:/users/{user_id}", {method: GET, path: /employee/{id}}]
      or a bare list at root.
    """
    path = os.path.join(config_dir, 'endpoints.yaml')
    if not os.path.exists(path):
        return []
    data = load_yaml(path)
    items = []
    raw = data.get('endpoints') if isinstance(data, dict) else data
    if not isinstance(raw, list):
        return []
    seen = set()
    for it in raw:
        try:
            if isinstance(it, str):
                if ':' not in it:
                    continue
                mth, pth = it.split(':', 1)
                m = mth.strip().upper()
                p = normalize_path(pth.strip())
            elif isinstance(it, dict):
                m = str(it.get('method') or 'GET').upper()
                p = normalize_path(str(it.get('path') or '/'))
            else:
                continue
            key = (m, p)
            if key in seen:
                continue
            seen.add(key)
            items.append({"method": m, "path": p})
        except Exception:
            continue
    return items

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

def extract_request_schema(openapi: Dict[str, Any], method: str, path: str) -> Dict[str, Any]:
    """
    Extract request body schema from OpenAPI spec for given method and path.
    Returns schema with required fields, properties, and examples.
    """
    try:
        # Normalize method and path
        method = method.upper()
        path = normalize_path(path)
        path_norm = path.rstrip('/') or '/'

        spec_paths = openapi.get('paths', {}) or {}
        operation = None

        # Local helper: resolve OpenAPI $ref recursively (best effort)
        def _resolve_ref(node: Dict[str, Any], max_depth: int = 8) -> Dict[str, Any]:
            cur = node if isinstance(node, dict) else {}
            depth = 0
            while isinstance(cur, dict) and '$ref' in cur and depth < max_depth:
                ref = cur.get('$ref')
                if not isinstance(ref, str) or not ref.startswith('#/'):
                    break
                parts = [p for p in ref[2:].split('/') if p]
                target = openapi
                ok = True
                for part in parts:
                    if isinstance(target, dict) and part in target:
                        target = target[part]
                    else:
                        ok = False
                        break
                if not ok or not isinstance(target, dict):
                    break
                cur = target
                depth += 1
            return cur if isinstance(cur, dict) else {}

        # Direct match first (with and without trailing slash)
        if path in spec_paths:
            operation = (spec_paths.get(path) or {}).get(method.lower())
        if not operation:
            for sp, item in spec_paths.items():
                if (normalize_path(sp).rstrip('/') or '/') == path_norm:
                    operation = (item or {}).get(method.lower())
                    if operation:
                        break

        # Pattern matching for parameterized paths
        if not operation:
            for spec_path, path_item in spec_paths.items():
                sp_norm = normalize_path(spec_path).rstrip('/') or '/'
                pattern = re.sub(r'\{[^}]+\}', r'[^/]+', sp_norm)
                if re.fullmatch(pattern, path_norm):
                    operation = (path_item or {}).get(method.lower())
                    if operation:
                        break

        if not operation:
            return {}

        request_body = operation.get('requestBody', {})
        request_body = _resolve_ref(request_body)
        if not request_body:
            return {}

        content = request_body.get('content', {}) or {}
        # Prefer JSON-like media types but support form data as fallback
        media = (
            content.get('application/json')
            or content.get('application/*+json')
            or content.get('application/x-www-form-urlencoded')
            or content.get('multipart/form-data')
            or {}
        )

        schema = _resolve_ref(media.get('schema', {}))
        # Resolve nested property refs as well
        if isinstance(schema.get('properties'), dict):
            for pk, pv in list(schema.get('properties', {}).items()):
                if isinstance(pv, dict) and '$ref' in pv:
                    schema['properties'][pk] = _resolve_ref(pv)

        # If no schema, try infer from example(s)
        if not schema or not schema.get('properties'):
            example = media.get('example', {})
            if not example and 'examples' in media:
                examples_obj = media.get('examples', {})
                if isinstance(examples_obj, dict) and examples_obj:
                    first_key = next(iter(examples_obj), None)
                    ex_item = examples_obj.get(first_key) if first_key else None
                    if isinstance(ex_item, dict):
                        example = ex_item.get('value', {})

            if example and isinstance(example, dict):
                schema = {'type': 'object', 'properties': {}, 'required': list(example.keys())}
                for key, value in example.items():
                    if isinstance(value, str):
                        schema['properties'][key] = {'type': 'string'}
                    elif isinstance(value, bool):
                        schema['properties'][key] = {'type': 'boolean'}
                    elif isinstance(value, int):
                        schema['properties'][key] = {'type': 'integer'}
                    elif isinstance(value, list):
                        schema['properties'][key] = {'type': 'array'}
                    elif isinstance(value, dict):
                        schema['properties'][key] = {'type': 'object'}
                    else:
                        schema['properties'][key] = {'type': 'string'}

        return {
            'schema': schema if isinstance(schema, dict) else {},
            'required': (schema.get('required', []) if isinstance(schema, dict) else []),
            'properties': (schema.get('properties', {}) if isinstance(schema, dict) else {}),
            'example': media.get('example') or media.get('examples', {})
        }
    except Exception:
        return {}

def generate_payload_from_schema(schema_info: Dict[str, Any], discovered_ids: Dict[str, Any] = None) -> Any:
    """
    Generate valid request payload from OpenAPI schema.
    Uses discovered resource IDs when available.
    Supports both object schemas (returns dict) and array schemas (returns list).
    
    Args:
        schema_info: Schema extracted from extract_request_schema() OR direct schema dict
        discovered_ids: Dict of discovered resource IDs by role
    
    Returns:
        Dict/List with valid payload or empty dict if schema unavailable
    """
    if not schema_info:
        return {}
    
    discovered_ids = discovered_ids or {}
    
    # Handle direct schema (type at top level) vs wrapped schema (type in 'schema' key)
    schema_type = schema_info.get('type')
    if not schema_type and 'schema' in schema_info:
        # Wrapped format: {'schema': {...}, 'properties': {}, 'required': []}
        actual_schema = schema_info.get('schema', {})
        schema_type = actual_schema.get('type')
    else:
        # Direct format: {'type': '...', 'properties': {}, ...}
        actual_schema = schema_info
    
    # Handle ARRAY schemas
    if schema_type == 'array':
        items_schema = actual_schema.get('items', {})
        if items_schema.get('type') == 'object':
            # Generate one object from items schema
            item_obj = _generate_default_value('object', items_schema, 'item')
            return [item_obj] if item_obj else []
        else:
            # Primitive array
            default_item = _generate_default_value(items_schema.get('type', 'string'), items_schema, 'item')
            return [default_item]
    
    # Handle OBJECT schemas (original logic)
    if not schema_info.get('properties') and not actual_schema.get('properties'):
        return {}
    
    schema = schema_info.get('schema', {})
    required_fields = schema_info.get('required', [])
    properties = schema_info.get('properties', {})
    
    # Start with example if available
    payload = {}
    if schema_info.get('example') and isinstance(schema_info['example'], dict):
        payload = dict(schema_info['example'])
    
    # Generate values for required fields
    for field_name in required_fields:
        if field_name in payload:
            continue  # Already have value from example
        
        field_schema = properties.get(field_name, {})
        field_type = field_schema.get('type', 'string')
        field_example = field_schema.get('example')
        
        # Use example if available
        if field_example is not None:
            payload[field_name] = field_example
            continue
        
        # Try to use discovered IDs for ID-like fields
        if 'id' in field_name.lower() and discovered_ids:
            # Extract resource type from field name
            # e.g., 'id_change_req' -> 'change_req', 'user_id' -> 'user'
            resource_token = field_name.lower().replace('id_', '').replace('_id', '')
            
            for resource_key, rid in discovered_ids.items():
                if resource_token in resource_key.lower():
                    payload[field_name] = rid
                    break
        
        # Generate default value based on type
        if field_name not in payload:
            payload[field_name] = _generate_default_value(field_type, field_schema, field_name)
    
    # Add optional fields with examples if available
    for field_name, field_schema in properties.items():
        if field_name in payload:
            continue  # Already filled
        
        # Only add optional fields if they have examples
        field_example = field_schema.get('example')
        if field_example is not None:
            payload[field_name] = field_example
    
    return payload

def _generate_default_value(field_type: str, field_schema: Dict[str, Any], field_name: str = '') -> Any:
    """Generate sensible default value based on JSON schema type."""
    import time
    import random
    
    # Check enum/allowed values
    enum_values = field_schema.get('enum', [])
    if enum_values:
        return enum_values[0]
    
    # Generate by type
    if field_type == 'string':
        # Check format
        fmt = field_schema.get('format', '')
        if fmt == 'email':
            # Add random suffix to avoid duplicate emails
            random_suffix = str(int(time.time() * 1000))[-6:]
            return f"test{random_suffix}@example.com"
        elif fmt == 'uri' or fmt == 'url':
            return "https://example.com"
        elif fmt == 'date':
            return "2024-01-01"
        elif fmt == 'date-time':
            return "2024-01-01T00:00:00Z"
        else:
            # Check if field name indicates unique value (role_name, permission_name, etc.)
            unique_keywords = ['name', 'username', 'login', 'title', 'code']
            is_unique_field = any(keyword in field_name.lower() for keyword in unique_keywords)
            
            if is_unique_field:
                # Add random suffix to avoid duplicates
                random_suffix = f"{int(time.time() * 1000) % 100000}{random.randint(10, 99)}"
                min_len = field_schema.get('minLength', 1)
                base_value = "x" * max(1, min_len - len(random_suffix) - 1)
                return f"{base_value}_{random_suffix}"
            else:
                # Regular string
                min_len = field_schema.get('minLength', 1)
                return "x" * max(1, min_len)
    
    elif field_type == 'integer' or field_type == 'number':
        minimum = field_schema.get('minimum', 1)
        return int(minimum)
    
    elif field_type == 'boolean':
        return True
    
    elif field_type == 'array':
        items_schema = field_schema.get('items', {})
        item_type = items_schema.get('type', 'string')
        
        # Generate array item based on type
        if item_type == 'object':
            # Generate object with properties
            props = items_schema.get('properties', {})
            item_obj = {}
            for prop_name, prop_schema in props.items():
                prop_type = prop_schema.get('type', 'string')
                item_obj[prop_name] = _generate_default_value(prop_type, prop_schema, prop_name)
            return [item_obj]  # Return array with one object
        else:
            # Primitive item type
            return [_generate_default_value(item_type, items_schema, '')]
    
    elif field_type == 'object':
        # Recursively generate object properties
        props = field_schema.get('properties', {})
        obj = {}
        for prop_name, prop_schema in props.items():
            prop_type = prop_schema.get('type', 'string')
            obj[prop_name] = _generate_default_value(prop_type, prop_schema, prop_name)
        return obj
    
    else:
        return None
