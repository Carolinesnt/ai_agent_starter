import os, json, datetime
from typing import List, Dict, Any
from .memory import Result, TestCase
from .evaluators import confusion_counts, metrics, coverage, time_to_detect, expected_status, classify

def save_json_report(path: str, results: List[Result], policy, tests: List[TestCase], roles: list, endpoints: list, start_ts: float = 0.0, reflection: Dict[str, Any] = None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
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
    # Use DD-MM-YYYY HH:MM format (UTC-based to preserve prior semantics)
    data = {
        "generated_at": datetime.datetime.utcnow().strftime("%d-%m-%Y %H:%M"),
        "confusion": cf,
        "metrics": m,
        "coverage": cov,
        "time_to_detect": ttd,
        "summary": {
            "total_tests": total_tests,
            "potential_vulnerabilities": pot_vulns,
        },
        "artifacts": artifacts,
        "reflection": reflection or {},
        "results": [{
            "method": r.tc.method, "path": r.tc.path, "role": r.tc.role,
            "self_access": r.tc.self_access, "status": r.status_code, "body": r.body, "ts": r.ts,
            "artifact": r.artifact
        } for r in results]
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    # Also write a brief Markdown summary next to the JSON report
    md_path = path.replace('.json', '.md')
    try:
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# BAC Test Report\n\n")
            f.write(f"Generated: {data['generated_at']}\n\n")
            f.write(f"## Summary\n- Total tests: {total_tests}\n- Potential vulns (FN): {pot_vulns}\n- Coverage: {cov['coverage_pct']}% of {cov['total_pairs']} pairs\n- Time to first detect (s): {ttd.get('seconds')}\n\n")
            f.write("## Confusion\n")
            f.write(f"- TP: {cf['TP']}\n- FP: {cf['FP']}\n- FN: {cf['FN']}\n- TN: {cf['TN']}\n\n")
            f.write("## Artifacts\n")
            for a in artifacts[:50]:
                f.write(f"- {a['method']} {a['path']} [{a['role']}] -> {a['artifact']}\n")
            if len(artifacts) > 50:
                f.write(f"... and {len(artifacts)-50} more\n")
    except Exception:
        pass
    return path
