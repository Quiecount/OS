"""防止阶段验收脚本把失败或自动化结果误报为成员独立验收通过。"""

from pathlib import Path
import sys
import tempfile
import unittest

from stage1_acceptance import StepFailure, finish_report, run_step


class Stage1AcceptanceTest(unittest.TestCase):
    def test_nonzero_step_fails_and_keeps_log(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with self.assertRaises(StepFailure) as caught:
                run_step("failure", [sys.executable, "-c", "print('diagnostic'); raise SystemExit(7)"], output)
            self.assertEqual(caught.exception.result["status"], "FAIL")
            self.assertEqual(caught.exception.result["exit_code"], 7)
            self.assertIn("diagnostic", (output / "failure.log").read_text())

    def test_timeout_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(StepFailure) as caught:
                run_step("timeout", [sys.executable, "-c", "import time; time.sleep(1)"],
                         Path(directory), timeout=0.05)
            self.assertEqual(caught.exception.result["status"], "FAIL")
            self.assertIn("error", caught.exception.result)

    def test_automated_success_keeps_human_pending(self):
        for succeeded in [True, False]:
            report = finish_report({"operator_label": "yu"}, succeeded)
            self.assertEqual(report["engineering_status"], "PASS" if succeeded else "FAIL")
            self.assertEqual(report["human_acceptance"], "PENDING")
            self.assertNotEqual(report["phase1_status"], "COMPLETE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
