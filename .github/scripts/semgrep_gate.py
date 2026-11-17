#!/usr/bin/env python3
"""Quality Gate SAST: falla el build si Semgrep reporta hallazgos ERROR/HIGH/CRITICAL."""
import collections
import json
import os
import sys

BLOCKING = {"ERROR", "HIGH", "CRITICAL"}

path = sys.argv[1] if len(sys.argv) > 1 else "semgrep-results.json"
if not os.path.exists(path):
    print(f"::error title=SAST Gate::No se encontro {path}; Semgrep no genero resultados")
    sys.exit(1)

with open(path, encoding="utf-8") as fh:
    results = json.load(fh).get("results", [])

by_sev = collections.Counter(r["extra"].get("severity", "UNKNOWN").upper() for r in results)
blocking = [r for r in results if r["extra"].get("severity", "").upper() in BLOCKING]

lines = [
    "## SAST - Semgrep",
    "",
    f"Total de hallazgos: **{len(results)}**  ",
    "Por severidad: " + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())),
    "",
]
if blocking:
    lines += ["### Hallazgos bloqueantes (ERROR/HIGH)", "", "| Regla | Archivo | Línea |", "|---|---|---|"]
    for r in blocking:
        rule = r["check_id"].split(".")[-1]
        lines.append(f"| `{rule}` | `{r['path']}` | {r['start']['line']} |")
        msg = r["extra"].get("message", "").replace("\n", " ")[:180]
        print(f"::error file={r['path']},line={r['start']['line']},title=Semgrep {rule}::{msg}")

summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
print("\n".join(lines))

if blocking:
    print(f"QUALITY GATE SAST: FAIL ({len(blocking)} hallazgos ERROR/HIGH)")
    sys.exit(1)
print("QUALITY GATE SAST: PASS")
