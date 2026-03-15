import os, json, datetime, time, re, csv
from typing import List, Dict, Any
from .memory import Result, TestCase
from .evaluators import confusion_counts, metrics, coverage, time_to_detect, expected_status, classify, roles_allowed_for_endpoint


def _parse_id_from_artifact(artifact_path: str, path_template: str) -> str:
    """Extract resolved ID from artifact path (e.g. users_22 -> 22, payroll_4 -> 4, leaves_111 -> 111)."""
    if not artifact_path:
        return ""
    path_norm = (artifact_path or "").replace("\\", "/")
    # segments like users_22, payroll_4, leaves_111, admin_audit-logs_4
    m = re.search(r"[/_](\d+)(?:_|\.|-|/|$)", path_norm)
    return m.group(1) if m else ""


def _scenario_description(role: str, path: str, method: str, self_access: bool, label: str, orig_id: str, mod_id: str) -> str:
    """Human-readable scenario description for submission."""
    role_lower = (role or "").strip().lower().replace("_", " ")
    p = (path or "").lower()
    if "user" in p and "role" not in p:
        resource = "user profile"
    elif "payroll" in p:
        resource = "payroll record"
    elif "leave" in p:
        resource = "leave request"
    elif "document" in p:
        resource = "document"
    elif "auth/me" in p:
        resource = "session/identity"
    elif "admin" in p or "audit" in p:
        resource = "admin/audit data"
    else:
        resource = "resource"
    if label == "FN" and not self_access:
        return f"{role_lower} attempts to access another user's {resource}"
    if label == "FN" and self_access:
        return f"{role_lower} accessed {resource} (expected deny)"
    if label == "TP" and self_access:
        return f"{role_lower} accesses own {resource} (baseline)"
    if label == "TP" and not self_access:
        return f"{role_lower} accesses other {resource} (allowed)"
    if label == "TN":
        return f"{role_lower} correctly denied access to {resource}"
    if label == "FP":
        return f"{role_lower} incorrectly denied access to {resource}"
    return f"{role_lower} {method} {path} (self={self_access}) -> {label}"


def _write_submission_csvs(report_path: str, endpoints: list, roles: list, artifacts: list, classified: dict, results: List[Result], policy) -> None:
    """Write critical_endpoints.csv and test_scenarios.csv to ai_agent/data/ for submission."""
    try:
        base = os.path.dirname(os.path.dirname(report_path))
        data_dir = os.path.join(base, "data")
        os.makedirs(data_dir, exist_ok=True)
    except Exception:
        return
    seen = set()
    ep_list = []
    for a in artifacts:
        m, p = (a.get("method") or "GET").upper(), (a.get("path") or "").strip()
        if not p or (m, p) in seen:
            continue
        seen.add((m, p))
        ep_list.append({"method": m, "path": p})
    path_to_id = {(e["method"], e["path"]): f"EP{i:03d}" for i, e in enumerate(ep_list, 1)}
    def _mod(p): return _path_to_module(p)
    def _res(p): return _path_to_resource_type(p)
    def _has_id(p): return "yes" if re.search(r"\{[^}]+\}", p or "") else "no"
    def _id_name(p): m = re.search(r"\{([^}]+)\}", p or ""); return m.group(1) if m else ""
    def _reason(p, m): return _critical_reason(p, m)

    with open(os.path.join(data_dir, "critical_endpoints.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["endpoint_id", "path", "http_method", "module", "resource_type", "contains_identifier", "identifier_name", "critical_reason", "allowed_roles", "test_priority"])
        for i, e in enumerate(ep_list, 1):
            p, m = e["path"], e["method"]
            roles_str = ",".join(roles_allowed_for_endpoint(policy, m, p))
            w.writerow([f"EP{i:03d}", p, m, _mod(p), _res(p), _has_id(p), _id_name(p), _reason(p, m), roles_str, "high" if _has_id(p) == "yes" or "admin" in p.lower() else "medium"])

    # Build test_scenarios from results so we have artifact path for original/modified identifier
    rows = []
    for idx, r in enumerate(results):
        try:
            exp = expected_status(policy, r.tc)
            label = classify(exp, r.status_code)
            if label == "TP_ALLOW":
                label = "TP"
            elif label == "NOT_FOUND":
                label = "NF"
            elif label == "ERROR":
                label = "ERR"
            elif label == "SKIP":
                continue
        except Exception:
            continue
        m = (r.tc.method or "GET").upper()
        p = (r.tc.path or "").strip()
        role = (r.tc.role or "").strip()
        sa = r.tc.self_access
        ep_id = path_to_id.get((m, p), "")
        has_placeholder = bool(re.search(r"\{[^}]+\}", p))
        if not sa and has_placeholder:
            vuln = "IDOR"
            action = "replace_identifier"
        elif label == "FN":
            vuln = "BOLA"
            action = "unauthorized_read" if m == "GET" else "unauthorized_write"
        elif label == "TP" and sa:
            vuln = "BASELINE"
            action = "self_access"
        else:
            vuln = "BOLA" if label == "TN" else "BOLA"
            action = "replace_identifier" if not sa else "self_access"
        exp_result = "allow" if label == "TP" else "deny"
        artifact_path = getattr(r, "artifact", None) or ""
        resolved_id = _parse_id_from_artifact(artifact_path, p)
        if sa:
            orig_id, mod_id = resolved_id, ""
        else:
            orig_id, mod_id = "", resolved_id
        resource_owner = role if sa else "other"
        desc = _scenario_description(role, p, m, sa, label, orig_id, mod_id)
        rows.append([f"SC{len(rows)+1:03d}", ep_id, vuln, role, resource_owner, action, orig_id, mod_id, exp_result, desc])
    with open(os.path.join(data_dir, "test_scenarios.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scenario_id", "endpoint_id", "vulnerability_type", "actor_role", "resource_owner_role", "test_action", "original_identifier", "modified_identifier", "expected_result", "scenario_description"])
        for row in rows:
            w.writerow(row)
    return


def _path_to_module(path: str) -> str:
    p = (path or "").strip().strip("/").split("/")
    if not p or not p[0]: return "root"
    if p[0].startswith("auth"): return "auth"
    if p[0].startswith("admin"): return "admin"
    return p[0] or "root"


def _path_to_resource_type(path: str) -> str:
    p = (path or "").lower()
    if "user" in p and "role" in p: return "user_role"
    if "user" in p: return "user_profile"
    if "payroll" in p: return "payroll_record"
    if "leave" in p: return "leave_workflow" if "approve" in p or "cancel" in p else "leave_request"
    if "document" in p: return "document_download" if "download" in p else "document"
    if "audit" in p: return "audit_log"
    if "dashboard" in p: return "dashboard"
    if "auth" in p: return "authentication"
    return "resource"


def _critical_reason(path: str, method: str) -> str:
    p, m = (path or "").lower(), (method or "").upper()
    r = []
    if re.search(r"\{[^}]+\}", path or ""): r.append("contains object identifier")
    if "payroll" in p: r.append("financial data")
    if "user" in p: r.append("PII/identity")
    if "admin" in p or "audit" in p: r.append("admin/audit scope")
    if "auth/me" in p: r.append("session disclosure")
    return "; ".join(r) if r else "tested endpoint"

def _build_offline_summary(
    cf: Dict[str, int],
    m: Dict[str, float],
    cov: Dict[str, Any],
    classified: Dict[str, list],
    total_tests: int,
    pot_vulns: int,
) -> str:
    """Build deterministic markdown summary when LLM is unavailable."""
    fp = int(cf.get("FP", 0))
    fn = int(cf.get("FN", 0))
    err = int(cf.get("ERR", 0))
    nf = int(cf.get("NF", 0))
    skip = int(cf.get("SKIP", 0))
    evaluated = int(m.get("evaluated_cases", max(1, total_tests)))
    fp_rate = (fp / max(1, evaluated)) * 100.0
    cov_pct = cov.get("coverage_pct", 0)

    if fn > 0:
        posture = "❌ **Poor**"
        immediate = "🚨 **YES**"
    elif fp > 0 or err > 0:
        posture = "⚠️ **Needs Improvement**"
        immediate = "⚠️ **Recommended**"
    else:
        posture = "✅ **Good**"
        immediate = "✅ **No**"

    high_vuln = classified.get("FN", [])[:3]
    high_fp = classified.get("FP", [])[:3]

    lines = []
    lines.append("# 🛡️ Security Assessment Summary: Broken Access Control (BAC) Report")
    lines.append("")
    lines.append("## 1. Executive Summary")
    lines.append(f"**Overall Security Posture:** {posture}  ")
    lines.append(
        f"Test execution completed with **{total_tests}** total outcomes and **{pot_vulns}** potential BAC vulnerabilities "
        f"(False Negatives). Coverage is **{cov_pct}%**."
    )
    lines.append("")
    lines.append(f"**Immediate Action Required:** {immediate}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 2. Vulnerability Analysis (False Negatives)")
    if high_vuln:
        for i, v in enumerate(high_vuln, start=1):
            lines.append(f"### 🚨 Vulnerability {i}")
            lines.append(f"*   **Endpoint:** `{v.get('method')} {v.get('path')}`")
            lines.append(f"*   **Role:** {v.get('role')}")
            lines.append("*   **Severity:** **High**")
            lines.append("*   **Risk:** Endpoint expected to be denied but returned allowed behavior.")
            lines.append("*   **Remediation:** Tighten RBAC policy/middleware and validate role checks on this handler.")
            lines.append("")
    else:
        lines.append("No false negatives detected in this run.")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 3. False Positives Review")
    lines.append(f"*   **Count:** {fp}")
    lines.append(f"*   **Estimated FP Rate:** {fp_rate:.1f}%")
    if high_fp:
        lines.append("*   **Examples:**")
        for it in high_fp:
            lines.append(f"    * `{it.get('method')} {it.get('path')}` [{it.get('role')}] -> {it.get('status')}")
    lines.append("*   **Fix:** Review endpoint allow-list/policy mapping and token role propagation.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 4. Performance Assessment")
    lines.append(f"*   **Coverage:** {cov_pct}% ({cov.get('covered_pairs', 0)}/{cov.get('total_pairs', 0)} role×endpoint pairs)")
    lines.append(f"*   **System Errors (5xx):** {err}")
    lines.append(f"*   **Not Found (404):** {nf}")
    lines.append(f"*   **Skipped/Inconclusive:** {skip}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 5. Recommendations (Prioritized)")
    lines.append("### **HIGH PRIORITY:**")
    lines.append("- [ ] Patch endpoints listed under FN to enforce deny decisions correctly.")
    lines.append("- [ ] Investigate and fix server-side 5xx paths first (stability + security).")
    lines.append("### **MEDIUM PRIORITY:**")
    lines.append("- [ ] Reduce FP by validating policy matrix and auth middleware mapping.")
    lines.append("- [ ] Normalize 401 vs 403 responses to reduce ambiguity.")
    lines.append("### **LOW PRIORITY:**")
    lines.append("- [ ] Reduce SKIP by improving dynamic ID discovery and fixture seeding.")
    lines.append("- [ ] Archive artifacts and keep regression comparisons per run.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 6. Security Best Practices Compliance")
    lines.append(f"*   **OWASP A01:2021 (Broken Access Control):** {'❌ FAIL' if fn > 0 else '✅ PASS'}")
    lines.append(f"*   **Principle of Least Privilege:** {'❌ FAIL' if fn > 0 else '⚠️ PARTIAL' if fp > 0 else '✅ PASS'}")
    lines.append(f"*   **Fail Secure:** {'✅ PASS' if fp > 0 else '⚠️ PARTIAL'}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 7. Next Steps")
    lines.append("1. Re-test FN endpoints after policy/controller fixes.")
    lines.append("2. Add endpoint-specific fixtures to reduce unresolved placeholders.")
    lines.append("3. Keep this test suite in CI to prevent BAC regressions.")
    lines.append("")
    lines.append("> Note: This summary is generated by deterministic offline fallback because LLM output was unavailable.")
    return "\n".join(lines)

def save_json_report(path: str, results: List[Result], policy, tests: List[TestCase], roles: list, endpoints: list, start_ts: float = 0.0, reflection: Dict[str, Any] = None, llm_summary: str = None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    # Calculate total execution duration
    end_ts = time.time()
    total_duration = round(end_ts - start_ts, 3) if start_ts > 0 else None
    
    cf = confusion_counts(results, policy)
    m = metrics(cf)
    cov = coverage(tests, roles, endpoints)
    ttd = time_to_detect(results, policy, start_ts)
    # Summaries
    total_tests = len(results)
    # Potential vulns per our conservative definition: expected deny but got 200 (classified as FN)
    pot_vulns = int(cf.get("FN", 0))
    # Collect artifacts mapping
    artifacts = []
    for r in results:
        artifacts.append({
            "method": r.tc.method,
            "path": r.tc.path,
            "role": r.tc.role,
            "artifact": r.artifact,
        })

    # Classify each result into TP/TN/FP/FN/NF/ERR lists
    classified: Dict[str, list] = {"TP": [], "TN": [], "FP": [], "FN": [], "NF": [], "ERR": [], "SKIP": []}
    for r in results:
        try:
            exp = expected_status(policy, r.tc)
            lab = classify(exp, r.status_code)
            # Normalize labels to keys above
            if lab == "TP_ALLOW":
                key = "TP"
            elif lab == "NOT_FOUND":
                key = "NF"
            elif lab == "ERROR":
                key = "ERR"
            elif lab == "SKIP":
                key = "SKIP"
            else:
                key = lab
            if key in classified:
                classified[key].append({
                    "method": r.tc.method,
                    "path": r.tc.path,
                    "role": r.tc.role,
                    "self_access": r.tc.self_access,
                    "status": r.status_code,
                })
        except Exception:
            continue
    # Use DD-MM-YYYY HH:MM format (UTC-based to preserve prior semantics)
    llm_text = (llm_summary or "").strip()
    llm_unavailable = (not llm_text) or llm_text.startswith("⚠️")
    effective_summary = llm_text if not llm_unavailable else _build_offline_summary(cf, m, cov, classified, total_tests, pot_vulns)
    data = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%d-%m-%Y %H:%M"),
        "confusion": cf,
        "metrics": m,
        "coverage": cov,
        "time_to_detect": ttd,
        "total_duration_seconds": total_duration,
        "summary": {
            "total_tests": total_tests,
            "potential_vulnerabilities": pot_vulns,
        },
        "llm_summary": effective_summary,
        "llm_summary_raw": llm_text,
        "llm_summary_fallback": bool(llm_unavailable),
        "artifacts": artifacts,
        "reflection": reflection or {},
        "classified": classified,
        "results": [{
            "method": r.tc.method, "path": r.tc.path, "role": r.tc.role,
            "self_access": r.tc.self_access, "status": r.status_code, "body": r.body, "ts": r.ts,
            "artifact": r.artifact
        } for r in results]
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        _write_submission_csvs(path, endpoints, roles, artifacts, classified, results, policy)
    except Exception:
        pass
    # Also write a comprehensive Markdown report with LLM summary
    md_path = path.replace('.json', '.md')
    try:
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# 🔒 BAC Security Test Report\n\n")
            f.write(f"**Generated:** {data['generated_at']}\n\n")
            f.write("---\n\n")
            
            # AI summary (LLM or deterministic fallback)
            f.write(f"## 🤖 AI Security Assessment\n\n")
            f.write(effective_summary)
            f.write("\n\n---\n\n")
            
            f.write(f"## 📊 Test Execution Summary\n\n")
            f.write(f"- **Total Tests:** {total_tests}\n")
            f.write(f"- **Potential Vulnerabilities (FN):** {pot_vulns} 🚨\n")
            f.write(f"- **Coverage:** {cov['coverage_pct']}% of {cov['total_pairs']} role×endpoint pairs\n")
            f.write(f"- **Total Execution Time:** {total_duration} seconds ⏱️\n")
            f.write(f"- **Time to First Detection:** {ttd.get('seconds')} seconds\n\n")
            
            f.write("## 🎯 Performance Metrics\n\n")
            f.write(f"- **Accuracy:** {round(m.get('accuracy', 0) * 100, 1)}%\n")
            f.write(f"- **Precision:** {round(m.get('precision', 0) * 100, 1)}%\n")
            f.write(f"- **Recall:** {round(m.get('recall', 0) * 100, 1)}%\n")
            f.write(f"- **F1 Score:** {round(m.get('f1', 0) * 100, 1)}%\n\n")
            
            f.write("## 📋 Confusion Matrix\n\n")
            f.write(f"- ✅ **TP (True Positives):** {cf['TP']} - Allowed endpoints working correctly\n")
            f.write(f"- ✅ **TN (True Negatives):** {cf['TN']} - Unauthorized access correctly blocked\n")
            f.write(f"- ⚠️ **FP (False Positives):** {cf['FP']} - Allowed endpoints incorrectly denied\n")
            f.write(f"- 🚨 **FN (False Negatives):** {cf['FN']} - **VULNERABILITIES DETECTED**\n")
            if cf.get('ERR', 0) > 0:
                f.write(f"- ❌ **ERR (System Errors):** {cf['ERR']} - 5xx responses\n")
            if cf.get('NF', 0) > 0:
                f.write(f"- ℹ️ **NF (Not Found):** {cf['NF']} - 404 responses (not BAC findings per OWASP)\n")
            if cf.get('SKIP', 0) > 0:
                f.write(f"- ⏭️ **SKIP (Inconclusive):** {cf['SKIP']} - Invalid/incomplete test outcomes excluded from core confusion labels\n")
            f.write("\n")
            
            # Endpoint lists by classification
            def _writelst(title: str, items: list, emoji: str = ""):
                f.write(f"### {emoji} {title} ({len(items)})\n\n")
                cap = 200
                for it in items[:cap]:
                    try:
                        sa = it.get('self_access')
                        so = 'self' if sa is True else ('other' if sa is False else '')
                    except Exception:
                        so = ''
                    suffix = f" {so}" if so else ''
                    f.write(f"- `{it['method']} {it['path']}` [{it['role']}{suffix}] → {it['status']}\n")
                if len(items) > cap:
                    f.write(f"\n... and {len(items)-cap} more\n\n")
                else:
                    f.write("\n")

            f.write("## 🧭 Endpoints by Classification\n\n")
            _writelst("TP (Allowed as expected)", classified.get('TP', []), "✅")
            _writelst("TN (Denied as expected)", classified.get('TN', []), "✅")
            _writelst("FP (Allowed expected but denied)", classified.get('FP', []), "⚠️")
            _writelst("FN (Denied expected but allowed) — Vulnerabilities", classified.get('FN', []), "🚨")
            if cf.get('NF', 0) > 0:
                _writelst("NF (Not Found)", classified.get('NF', []), "ℹ️")
            if cf.get('ERR', 0) > 0:
                _writelst("ERR (5xx System Errors)", classified.get('ERR', []), "❌")
            if cf.get('SKIP', 0) > 0:
                _writelst("SKIP (Inconclusive outcomes)", classified.get('SKIP', []), "⏭️")

            f.write("## 📁 Test Artifacts\n\n")
            f.write("Full request/response artifacts saved for forensic analysis:\n\n")
            for a in artifacts[:50]:
                f.write(f"- `{a['method']} {a['path']}` [{a['role']}] → {a['artifact']}\n")
            if len(artifacts) > 50:
                f.write(f"\n... and {len(artifacts)-50} more artifacts\n")
    except Exception:
        pass
    return path
