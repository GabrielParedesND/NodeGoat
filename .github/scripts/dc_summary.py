#!/usr/bin/env python3
"""Resume el reporte JSON de OWASP Dependency-Check (CVSS >= 7) en el Job Summary."""
import json
import os
import sys

THRESHOLD = float(os.environ.get("SCA_FAIL_CVSS", "7"))
path = sys.argv[1] if len(sys.argv) > 1 else "reports/dependency-check-report.json"
if not os.path.exists(path):
    print(f"No se encontro {path}")
    sys.exit(0)


def score(v):
    for key in ("cvssv4", "cvssv3", "cvssv2"):
        data = v.get(key) or {}
        s = data.get("baseScore") or data.get("score")
        if s is not None:
            return float(s)
    sev = (v.get("severity") or "").upper()
    return {"CRITICAL": 9.0, "HIGH": 7.5, "MODERATE": 5.0, "MEDIUM": 5.0, "LOW": 3.0}.get(sev, 0.0)


with open(path, encoding="utf-8") as fh:
    report = json.load(fh)

rows, total, suppressed = [], 0, 0
for dep in report.get("dependencies", []):
    suppressed += len(dep.get("suppressedVulnerabilities", []) or [])
    for v in dep.get("vulnerabilities", []) or []:
        total += 1
        s = score(v)
        if s >= THRESHOLD:
            rows.append((s, dep.get("fileName", "?"), v.get("name", "?")))

rows.sort(reverse=True)
lines = [
    "## SCA - OWASP Dependency-Check",
    "",
    f"Vulnerabilidades abiertas: **{total}** | CVSS >= {THRESHOLD}: **{len(rows)}** | Suprimidas (documentadas): **{suppressed}**",
    "",
]
if rows:
    lines += ["| CVSS | Dependencia | Vulnerabilidad |", "|---|---|---|"]
    lines += [f"| {s:.1f} | `{f}` | {n} |" for s, f, n in rows[:60]]
    if len(rows) > 60:
        lines.append(f"| ... | ({len(rows) - 60} más en el reporte HTML) | |")

summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
print("\n".join(lines))
