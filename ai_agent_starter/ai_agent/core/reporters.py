import os, json, datetime
from typing import List, Dict, Any
from .memory import Result, TestCase
from .evaluators import confusion_counts, metrics, coverage, time_to_detect, expected_status, classify

def save_json_report(path: str, results: List[Result], policy, tests: List[TestCase], roles: list, endpoints: list, start_ts: float = 0.0, reflection: Dict[str, Any] = None, llm_summary: str = None):
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
        "llm_summary": llm_summary or "",
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
    # Also write a comprehensive Markdown report with LLM summary
    md_path = path.replace('.json', '.md')
    try:
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# 🔒 BAC Security Test Report\n\n")
            f.write(f"**Generated:** {data['generated_at']}\n\n")
            f.write("---\n\n")
            
            # LLM Summary (if available)
            if llm_summary:
                f.write(f"## 🤖 AI Security Assessment\n\n")
                f.write(llm_summary)
                f.write("\n\n---\n\n")
            
            f.write(f"## 📊 Test Execution Summary\n\n")
            f.write(f"- **Total Tests:** {total_tests}\n")
            f.write(f"- **Potential Vulnerabilities (FN):** {pot_vulns} 🚨\n")
            f.write(f"- **Coverage:** {cov['coverage_pct']}% of {cov['total_pairs']} role×endpoint pairs\n")
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
            f.write("\n")
            
            f.write("## 📁 Test Artifacts\n\n")
            f.write("Full request/response artifacts saved for forensic analysis:\n\n")
            for a in artifacts[:50]:
                f.write(f"- `{a['method']} {a['path']}` [{a['role']}] → {a['artifact']}\n")
            if len(artifacts) > 50:
                f.write(f"\n... and {len(artifacts)-50} more artifacts\n")
    except Exception:
        pass
    return path
