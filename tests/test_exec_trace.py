"""在 openEuler 内核上验证 exec 探针；需 root/BPF 权限，先构建 src。"""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


BINARY = Path(__file__).resolve().parents[1] / "src/.output/exec_trace"
TRUE = shutil.which("true")


class ExecTraceTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(BINARY.is_file(), "请先执行 make -C src")
        self.assertIsNotNone(TRUE)
        self.temp = tempfile.TemporaryDirectory(prefix="osmedic-exec-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def start_trace(self, *args):
        output = self.directory / "stdout.jsonl"
        log = self.directory / "stderr.log"
        with output.open("wb") as stdout, log.open("wb") as stderr:
            proc = subprocess.Popen([str(BINARY), *args], stdout=stdout, stderr=stderr)
        self.addCleanup(self.terminate, proc)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if "Tracing successful exec events" in log.read_text():
                return proc, output, log
            if proc.poll() is not None:
                self.fail("探针启动失败（需要 BPF 权限）：\n" + log.read_text())
            time.sleep(0.05)
        self.fail("探针启动超时：\n" + log.read_text())

    @staticmethod
    def terminate(proc):
        if proc.poll() is None:
            proc.send_signal(signal.SIGCONT)
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

    def stop_trace(self, proc, log):
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        self.assertEqual(proc.wait(timeout=3), 0, log.read_text())
        self.assertRegex(log.read_text(), r"events_written=\d+ ringbuf_dropped=0")

    @staticmethod
    def records(path):
        return [json.loads(line) for line in path.read_text().splitlines()]

    def test_successful_exec_and_failed_exec(self):
        destination = self.directory / "events.jsonl"
        # 已有文件必须追加；没有新事件时也不能损坏原记录。
        destination.write_text('{"previous":true}\n')
        proc, stdout, log = self.start_trace("-o", str(destination))
        child = subprocess.Popen([TRUE])
        self.assertEqual(child.wait(timeout=3), 0)
        failed = os.fork()
        if failed == 0:
            try:
                os.execv("/osmedic-nonexistent-executable", ["missing"])
            except OSError:
                os._exit(0)
            os._exit(1)
        _, status = os.waitpid(failed, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.stop_trace(proc, log)
        rows = self.records(destination)
        self.assertEqual(rows[0], {"previous": True})
        matching = [row for row in rows[1:] if row["pid"] == child.pid]
        self.assertEqual(len(matching), 1)
        event = matching[0]
        self.assertEqual(event["event"], "process_exec")
        self.assertEqual(event["ppid"], os.getpid())
        self.assertEqual(event["uid"], os.getuid())
        self.assertEqual(event["filename"], TRUE)
        self.assertEqual(event["comm"], "true")
        self.assertGreater(event["timestamp_ns"], 0)
        self.assertEqual(event["clock"], "monotonic")
        self.assertFalse(event["filename_truncated"])
        self.assertFalse(event["filename_error"])
        self.assertNotIn(failed, [row["pid"] for row in rows[1:]])
        self.assertEqual(stdout.read_bytes(), b"")

    def test_pid_filter_and_stdout(self):
        read_fd, write_fd = os.pipe()
        target = os.fork()
        if target == 0:
            os.close(write_fd)
            ready = os.read(read_fd, 1)
            os.close(read_fd)
            if ready:
                os.execv(TRUE, [TRUE])
            os._exit(1)
        os.close(read_fd)
        try:
            proc, stdout, log = self.start_trace("--pid", str(target), "--output", "-")
            subprocess.run([TRUE], check=True, timeout=3)
            os.write(write_fd, b"1")
        finally:
            os.close(write_fd)
            _, status = os.waitpid(target, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.stop_trace(proc, log)
        rows = self.records(stdout)
        self.assertEqual([row["pid"] for row in rows], [target])
        self.assertEqual(rows[0]["filename"], TRUE)

    def test_filename_escaping(self):
        proc, stdout, log = self.start_trace()
        paths = [
            self.directory / 'quote"-backslash\\-newline\n-雪',
            os.fsencode(self.directory) + b"/invalid-\xff",
        ]
        children = []
        for path in paths:
            shutil.copyfile(os.fsencode(TRUE), os.fsencode(path))
            os.chmod(path, 0o700)
            child = subprocess.Popen([path])
            self.assertEqual(child.wait(timeout=3), 0)
            children.append(child.pid)
        self.stop_trace(proc, log)
        rows = {row["pid"]: row for row in self.records(stdout)}
        self.assertEqual(rows[children[0]]["filename"], str(paths[0]))
        self.assertEqual(rows[children[1]]["filename"], paths[1].decode("latin1"))
        self.assertIn(b"\\u000a", stdout.read_bytes())
        self.assertIn(b"\\u00ff", stdout.read_bytes())

    def test_long_filename_is_marked(self):
        directory = self.directory / ("a" * 90) / ("b" * 90) / ("c" * 90)
        directory.mkdir(parents=True)
        executable = directory / "true"
        shutil.copyfile(TRUE, executable)
        executable.chmod(0o700)
        proc, stdout, log = self.start_trace()
        child = subprocess.Popen([executable])
        self.assertEqual(child.wait(timeout=3), 0)
        self.stop_trace(proc, log)
        rows = [row for row in self.records(stdout) if row["pid"] == child.pid]
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["filename_truncated"])
        self.assertFalse(rows[0]["filename_error"])
        self.assertEqual(rows[0]["filename"], str(executable)[:255])

    def test_output_failure_returns_error(self):
        proc, _, log = self.start_trace("-o", "/dev/full")
        subprocess.run([TRUE], check=True, timeout=3)
        self.assertNotEqual(proc.wait(timeout=3), 0)
        self.assertIn("exec_trace failed", log.read_text())

    def test_cli_validation(self):
        result = subprocess.run([str(BINARY), "--help"], capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0)
        for pid in ["0", "-1", "abc", "2147483648", "1abc"]:
            with self.subTest(pid=pid):
                result = subprocess.run(
                    [str(BINARY), "-p", pid], capture_output=True, timeout=3
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Invalid PID", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
