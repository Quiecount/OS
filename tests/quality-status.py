#!/usr/bin/env python3
"""Read-only compact status for a long quality evaluation."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
folder = Path((root / "output/quality/latest.txt").read_text().strip())
report = json.loads((folder / "report.json").read_text())
cases = report["cases"]
# Diagnosis cases use the normal Top-10 display, so summing their visible
# rows is not a measurement of all calls. Count phases request all 4096 rows.
counts = [check for case in cases if not case["label"].startswith("diagnosis-")
          for check in case.get("count_checks", [])]
accuracy = {}
for field in ("syscall_latency", "offcpu", "runqlat", "cpu_accuracy"):
    entries = [(case["label"], case[field]) for case in cases if field in case]
    accuracy[field] = {"tested": len(entries), "failures": [name for name, item in entries
        if any(value is False for key, value in item.items() if key.endswith("target_met"))]}
print(json.dumps({"folder": str(folder), "profile": report["profile"],
    "active_phase": report.get("active_phase"), "finished_at": report.get("finished_at"),
    "cases_completed": len(cases),
    "execution_failures": [c["label"] for c in cases if c["execution"] != "passed"],
    "count_max_error_percent": max((c["error_percent"] for c in counts), default=None),
    "accuracy": accuracy, "diagnosis": report.get("diagnosis_progress"),
    "performance": report.get("performance_progress")}, ensure_ascii=False))
