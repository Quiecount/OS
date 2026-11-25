"""Contract check for loader diagnosis rows and the final report."""

import json
import unittest

from analysis.collector import collect


class CollectorContractTest(unittest.TestCase):
    def test_two_scene_diagnoses_become_report_anomalies(self):
        window = {"start": "2026-11-19T00:00:00Z",
                  "end": "2026-11-19T00:00:01Z"}
        rows = []
        for scene, kind, metrics in [
            ("syscall", "SYSCALL_HOTSPOT",
             {"calls_per_sec": 12000, "baseline_calls_per_sec": 1000,
              "top_syscall_id": 262, "top_pid": 123}),
            ("cpu", "CPU_HOG", {"cpu_percent": 95, "pid": 456}),
        ]:
            rows.append(json.dumps({
                "scene": scene, "ts_ns": 1, "pid": 123, "uid": 0,
                "comm": "test", "event": "diagnosis", "window": window,
                "type": kind, "related_objects": [{"kind": "process"}],
                "key_metrics": metrics, "suspected_root_cause": "load",
                "evidence_chain": ["metric"], "recommendation": ["inspect"],
            }))
        report = collect(rows)
        self.assertEqual(report["tool"], "osmedic")
        self.assertEqual(report["window"], window)
        self.assertEqual({a["type"] for a in report["anomalies"]},
                         {"SYSCALL_HOTSPOT", "CPU_HOG"})
        self.assertTrue(all(a["confidence"] == 1.0
                            for a in report["anomalies"]))

    def test_invalid_json_fails_closed(self):
        with self.assertRaises(ValueError):
            collect(["not JSON"])


if __name__ == "__main__":
    unittest.main()
