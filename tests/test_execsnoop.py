"""验证 GitLab 接口契约 B：execsnoop JSONL、限时、pretty 与错误退出。"""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build/execsnoop"
TRUE = shutil.which("true")


class ExecsnoopTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(BINARY.is_file(), "请先在仓库根目录 make")
        self.temp = tempfile.TemporaryDirectory(prefix="execsnoop-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    @staticmethod
    def terminate(proc):
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

    def start_trace(self, *args, output_path=None):
        output = output_path or self.directory / "stdout.jsonl"
        log = self.directory / "stderr.log"
        with open(output, "wb") as stdout, log.open("wb") as stderr:
            proc = subprocess.Popen([str(BINARY), *args], stdout=stdout, stderr=stderr, cwd=ROOT)
        self.addCleanup(self.terminate, proc)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if "[execsnoop] ready" in log.read_text():
                return proc, output, log
            if proc.poll() is not None:
                self.fail("加载失败（需要 BPF 权限）：\n" + log.read_text())
            time.sleep(0.02)
        self.fail("启动超时：\n" + log.read_text())

    def stop_trace(self, proc, log):
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=3), 0, log.read_text())

    @staticmethod
    def records(output):
        return [json.loads(line) for line in output.read_text().splitlines()]

    def test_jsonl_contract_and_collector_input(self):
        proc, output, log = self.start_trace()
        child = subprocess.Popen([TRUE])
        self.assertEqual(child.wait(timeout=3), 0)
        failed = os.fork()
        if failed == 0:
            try:
                os.execv("/osmedic-missing-executable", ["missing"])
            except OSError:
                os._exit(0)
            os._exit(1)
        _, status = os.waitpid(failed, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.stop_trace(proc, log)
        rows = self.records(output)
        for row in rows:
            self.assertEqual(list(row), ["scene", "ts_ns", "pid", "uid", "comm", "filename"])
            self.assertEqual(row["scene"], "exec")
            self.assertGreater(row["ts_ns"], 0)
            self.assertIsInstance(row["pid"], int)
            self.assertIsInstance(row["uid"], int)
            self.assertIsInstance(row["comm"], str)
        selected = [row for row in rows if row["pid"] == child.pid]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["filename"], TRUE)
        self.assertEqual(selected[0]["uid"], os.getuid())
        self.assertEqual([row["filename"] for row in rows if row["pid"] == failed],
                         ["/osmedic-missing-executable"])
        collector = subprocess.run(
            [sys.executable, "analysis/collector.py"], cwd=ROOT,
            input=output.read_bytes(), capture_output=True, timeout=3, check=True,
        )
        counts = json.loads(collector.stdout)["event_counts"]
        self.assertEqual(counts, {"exec": len(rows)})

    def test_duration_exit(self):
        started = time.monotonic()
        proc, output, log = self.start_trace("--duration", "1")
        subprocess.run([TRUE], check=True, timeout=3)
        self.assertEqual(proc.wait(timeout=3), 0, log.read_text())
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.9)
        self.assertLess(elapsed, 3)
        self.assertTrue(self.records(output))

    def test_pretty_output(self):
        proc, output, log = self.start_trace("--pretty")
        subprocess.run([TRUE], check=True, timeout=3)
        self.stop_trace(proc, log)
        lines = output.read_text().splitlines()
        self.assertIn("PID", lines[0])
        self.assertIn("FILENAME", lines[0])
        self.assertTrue(any(TRUE in line for line in lines[1:]))
        self.assertFalse(any(line.startswith("{") for line in lines))

    def test_filename_escaping(self):
        proc, output, log = self.start_trace()
        path = self.directory / 'quote"-backslash\\-newline\n-雪'
        shutil.copyfile(TRUE, path)
        path.chmod(0o700)
        child = subprocess.Popen([path])
        self.assertEqual(child.wait(timeout=3), 0)
        self.stop_trace(proc, log)
        selected = [row for row in self.records(output) if row["pid"] == child.pid]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["filename"], str(path))
        self.assertIn(b"\\u000a", output.read_bytes())

    def test_output_failure(self):
        proc, _, log = self.start_trace(output_path=Path("/dev/full"))
        subprocess.run([TRUE], check=True, timeout=3)
        self.assertNotEqual(proc.wait(timeout=3), 0)
        self.assertIn("[execsnoop] failed", log.read_text())

    def test_cli_validation(self):
        result = subprocess.run([str(BINARY), "--help"], capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0)
        for value in ["0", "-1", "abc", "1.5", "86401", "", "1abc"]:
            with self.subTest(value=value):
                result = subprocess.run([str(BINARY), "--duration", value],
                                        capture_output=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Invalid duration", result.stderr)
        result = subprocess.run([str(BINARY), "unexpected"], capture_output=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
