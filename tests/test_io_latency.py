"""真实内核 IO 探针集成测试；仅在被忽略的构建目录创建普通文件。"""

import json
import mmap
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest


BINARY = Path(__file__).resolve().parents[1] / "src/.output/io_latency"
IO_SIZE = 64 * 1024
IO_BLOCKS = 8


def request_devices(device_number):
    """将文件系统设备沿 slaves/partition 解析到请求队列所在整盘。"""
    device = Path(f"/sys/dev/block/{os.major(device_number)}:{os.minor(device_number)}")
    if not device.exists():
        raise RuntimeError("测试目录必须位于真实块设备文件系统，不能使用 tmpfs/overlay")
    device = device.resolve()
    if (device / "partition").exists():
        device = device.parent
    slaves = list((device / "slaves").iterdir()) if (device / "slaves").exists() else []
    if not slaves:
        return [device.joinpath("dev").read_text().strip()]
    result = []
    for slave in slaves:
        major, minor = map(int, slave.joinpath("dev").read_text().split(":"))
        result.extend(request_devices(os.makedev(major, minor)))
    return sorted(set(result))


class IOLatencyTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(BINARY.is_file(), "请先执行 make -C src io_latency")
        self.temp = tempfile.TemporaryDirectory(prefix="io-latency-", dir=BINARY.parent)
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

    def start_trace(self, *args):
        stdout = self.directory / "stdout.jsonl"
        log = self.directory / "stderr.log"
        with stdout.open("wb") as output, log.open("wb") as stderr:
            proc = subprocess.Popen([str(BINARY), *args], stdout=output, stderr=stderr)
        self.addCleanup(self.terminate, proc)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if "Tracing block IO latency" in log.read_text():
                return proc, stdout, log
            if proc.poll() is not None:
                self.fail("探针启动失败（需 BPF 权限）：\n" + log.read_text())
            time.sleep(0.05)
        self.fail("探针启动超时：\n" + log.read_text())

    def direct_io(self):
        # /tmp 在本机是 tmpfs；直接使用构建目录内的普通文件，绝不写块设备节点。
        path = self.directory / "workload.bin"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_DIRECT, 0o600)
        try:
            with mmap.mmap(-1, IO_SIZE) as buffer:
                buffer[:] = b"i" * IO_SIZE
                for index in range(IO_BLOCKS):
                    self.assertEqual(os.pwritev(fd, [buffer], index * IO_SIZE), IO_SIZE)
                os.fsync(fd)
                for index in range(IO_BLOCKS):
                    self.assertEqual(os.preadv(fd, [buffer], index * IO_SIZE), IO_SIZE)
                    self.assertEqual(buffer[:16], b"i" * 16)
        finally:
            os.close(fd)
            path.unlink()

    def stop_trace(self, proc, log):
        proc.send_signal(signal.SIGINT)
        self.assertEqual(proc.wait(timeout=3), 0, log.read_text())
        self.assertIn("tracking_failures=0", log.read_text())

    def read_snapshots(self, path):
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        for row in rows:
            if "event" not in row:
                continue
            self.assertEqual(row["event"], "block_io_latency")
            self.assertEqual(row["clock"], "monotonic")
            self.assertTrue(row["cumulative"])
            self.assertEqual(row["bucket_scale"], "log2_us")
            self.assertEqual(len(row["histogram"]), 32)
            self.assertTrue(all(isinstance(n, int) and n >= 0 for n in row["histogram"]))
            self.assertEqual(row["requests"], sum(row["histogram"]))
            self.assertGreaterEqual(row["window"]["end_ns"], row["window"]["start_ns"])
            if row["final"]:
                self.assertLessEqual(row["errors"], row["requests"])
                # 最终快照的延迟总和必须落在直方图各桶给出的总范围内。
                lower = sum(n * (0 if i == 0 else (1 << i) * 1000)
                            for i, n in enumerate(row["histogram"]))
                self.assertGreaterEqual(row["latency_total_ns"], lower)
                if row["requests"] and not row["histogram"][-1]:
                    upper = sum(n * (1 << (i + 1)) * 1000
                                for i, n in enumerate(row["histogram"]))
                    self.assertLess(row["latency_total_ns"], upper)
        return rows

    def test_read_write_device_and_signal(self):
        devices = request_devices(self.directory.stat().st_dev)
        self.assertEqual(len(devices), 1, "此定量用例需要单个底层请求设备")
        major, minor = map(int, devices[0].split(":"))
        proc, stdout, log = self.start_trace("-d", devices[0], "-i", "3600")
        self.direct_io()
        self.stop_trace(proc, log)
        rows = self.read_snapshots(stdout)
        self.assertEqual({row["operation"] for row in rows}, {"read", "write"})
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertTrue(row["final"])
            self.assertEqual(row["device"], {"major": major, "minor": minor})
            self.assertGreater(row["requests"], 0)
            self.assertGreaterEqual(row["bytes"], IO_SIZE * IO_BLOCKS)
            self.assertGreater(row["latency_total_ns"], 0)
            self.assertEqual(row["errors"], 0)
        print(f"  observed device={devices[0]} " + " ".join(
            f'{row["operation"]}:requests={row["requests"]},bytes={row["bytes"]}' for row in rows))

    def test_nonmatching_device(self):
        self.assertFalse(Path("/sys/dev/block/4095:1048575").exists())
        proc, stdout, log = self.start_trace("-d", "4095:1048575", "-i", "3600")
        self.direct_io()
        self.stop_trace(proc, log)
        rows = self.read_snapshots(stdout)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["requests"] == row["bytes"] == row["latency_total_ns"] == 0
                            for row in rows))
        self.assertIn("unfinished=0", log.read_text())

    def test_periodic_snapshots_and_append(self):
        destination = self.directory / "snapshots.jsonl"
        destination.write_text('{"previous":true}\n')
        proc, stdout, log = self.start_trace("-n", "2", "-o", str(destination))
        self.direct_io()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and len(destination.read_text().splitlines()) < 3:
            time.sleep(0.05)
        self.assertGreaterEqual(len(destination.read_text().splitlines()), 3)
        self.direct_io()
        self.assertEqual(proc.wait(timeout=4), 0, log.read_text())
        rows = self.read_snapshots(destination)
        self.assertEqual(rows.pop(0), {"previous": True})
        self.assertEqual(len(rows), 4)
        self.assertEqual([row["final"] for row in rows], [False, False, True, True])
        for before, after in zip(rows[:2], rows[2:]):
            self.assertEqual(before["operation"], after["operation"])
            self.assertEqual(before["window"]["start_ns"], after["window"]["start_ns"])
            self.assertGreater(after["window"]["end_ns"], before["window"]["end_ns"])
            self.assertGreater(after["requests"], before["requests"])
            self.assertGreater(after["bytes"], before["bytes"])
            self.assertTrue(all(a >= b for a, b in zip(after["histogram"], before["histogram"])))
            self.assertIsNone(after["device"])
        self.assertEqual(stdout.read_bytes(), b"")
        self.assertIn("tracking_failures=0", log.read_text())

    def test_output_failure(self):
        proc, _, log = self.start_trace("-n", "1", "-o", "/dev/full")
        self.assertNotEqual(proc.wait(timeout=3), 0)
        self.assertIn("io_latency failed", log.read_text())

    def test_cli_validation(self):
        result = subprocess.run([str(BINARY), "--help"], capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0)
        for option, values in {
            "-d": ["sda", "8", "8:", ":0", "-1:0", "4096:0", "8:1048576", "8:0:1"],
            "-i": ["0", "-1", "3601", "1.5", "abc"],
            "-n": ["0", "-1", "1000001", "abc"],
        }.items():
            for value in values:
                with self.subTest(option=option, value=value):
                    result = subprocess.run([str(BINARY), option, value], capture_output=True, timeout=3)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b"Invalid", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
