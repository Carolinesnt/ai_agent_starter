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

    def _artifact_path(self, name: str) -> str:
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

    def request(self, method: str, path: str, token: Optional[str], params=None, json_body=None, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
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
                # Simpan artefak
                ts = int(time.time()*1000)
                safe = path.strip('/').replace('/','_').replace('?','_').replace('&','_').replace('=','-')
                name = f"{ts}_{method}_{safe}.json"
                with open(self._artifact_path(name), "w", encoding="utf-8") as f:
                    json.dump({"request": {"method": method, "url": url, "headers": self._mask_headers_for_artifact(headers), "params": params, "json": json_body},
                               "response": resp}, f, indent=2)
                resp["artifact"] = os.path.join(self.artifacts_dir, name)
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
