#!/usr/bin/env python3
"""阶段2：真实探针 + 已知 PID/地址/样本数的有界负载，包含反例和清理。"""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build'
BINARIES = ['syscall_hotspot', 'cpu_hog', 'io_latency', 'mem_pressure', 'lock_contention']


class Stage2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise unittest.SkipTest('需要 root 进行真实 BPF 集成验证')
        subprocess.run(['make', '-s', '-C', str(ROOT), 'all', 'build/stage2_workload'], check=True)
        cls.artifacts = Path(tempfile.mkdtemp(prefix='stage2-', dir=BUILD))
        print(f'验收产物：{cls.artifacts}', flush=True)

    def workload(self, mode, *args):
        child = subprocess.Popen([str(BUILD / 'stage2_workload'), mode, *map(str, args)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True)
        self.addCleanup(self.stop_process, child)
        identity = json.loads(child.stdout.readline())
        self.assertEqual(identity['pid'], child.pid)
        return child, identity

    @staticmethod
    def stop_process(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream:
                stream.close()

    def monitor(self, binary, seconds=3, *args):
        name = f'{self._testMethodName}-{binary}'
        path = self.artifacts / f'{name}.jsonl'
        log = self.artifacts / f'{name}.log'
        stdout, stderr = path.open('w'), log.open('w')
        self.addCleanup(stdout.close)
        self.addCleanup(stderr.close)
        proc = subprocess.Popen([str(BUILD / binary), '--duration', str(seconds), *args], stdout=stdout, stderr=stderr)
        self.addCleanup(self.stop_process, proc)
        deadline = time.monotonic() + 10
        while '已启动' not in log.read_text():
            self.assertIsNone(proc.poll(), log.read_text())
            self.assertLess(time.monotonic(), deadline, log.read_text())
            time.sleep(.02)
        return proc, path

    def finish(self, proc, path, allow_empty=False):
        self.assertEqual(proc.wait(timeout=12), 0, path.with_suffix('.log').read_text())
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        if not allow_empty:
            self.assertTrue(rows)
        for row in rows:
            self.assertTrue({'scene', 'ts_ns', 'pid', 'uid', 'comm', 'window', 'event'} <= row.keys())
            self.assertGreater(row['ts_ns'], 0)
            self.assertTrue(row['window']['start'] and row['window']['end'])
        health = [r for r in rows if r['event'] == 'telemetry']
        if health:
            self.assertTrue(all(not r['window_incomplete'] for r in health), health)
            self.assertTrue(all(r['ringbuf_dropped'] == r['tracking_failures'] == r['aggregation_dropped'] == 0 for r in health))
        return rows

    def report(self, path, expected):
        result = subprocess.run(['python3', str(ROOT / 'analysis/collector.py'), '--input', str(path)], capture_output=True, text=True, check=True)
        report = json.loads(result.stdout)
        self.assertTrue(any(a['type'] == expected for a in report['anomalies']), expected)
        for a in report['anomalies']:
            self.assertTrue({'type', 'confidence', 'related_objects', 'key_metrics', 'suspected_root_cause', 'evidence_chain', 'recommendation'} <= a.keys())
        path.with_suffix('.report.json').write_text(result.stdout)

    def test_cli_duration_pretty_and_errors(self):
        for binary in BINARIES:
            with self.subTest(binary=binary):
                for bad in ['-1', 'abc', '1.2', '99999999999999999999999']:
                    result = subprocess.run([str(BUILD / binary), '--duration', bad], capture_output=True)
                    self.assertEqual(result.returncode, 1)
                    self.assertFalse(result.stdout)
                start = time.monotonic()
                result = subprocess.run([str(BUILD / binary), '--duration', '1', '--interval', '10', '--pretty'], capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertLess(time.monotonic() - start, 3, 'duration不应等待整个interval')
                self.assertNotIn('"scene":', result.stdout)
                result = subprocess.run([str(BUILD / binary), '-d', '1', '-o', '/dev/full'], capture_output=True, timeout=8)
                self.assertEqual(result.returncode, 1, '写失败不能报告成功')

    def test_io_known_bytes_and_attribution(self):
        filename = self.artifacts / 'direct-io.img'
        child, identity = self.workload('io', filename)
        monitor, path = self.monitor('io_latency', 3, '--pid', str(child.pid), '--histogram', '--baseline-p99-us', '0.001')
        child.stdin.write('g\n'); child.stdin.flush()
        self.assertEqual(child.wait(timeout=8), 0, child.stderr.read())
        rows = self.finish(monitor, path)
        metrics = [r for r in rows if r['event'] == 'io_metric' and r['operation'] == 'write']
        self.assertTrue(metrics)
        devices = {}
        for r in metrics:
            self.assertEqual(r['pid'], identity['pid'])
            self.assertEqual(r['uid'], os.getuid())
            self.assertEqual(r['samples'], sum(r['latency_buckets']))
            self.assertGreater(r['mean_ns'], 0)
            self.assertGreaterEqual(r['p99_ns'], r['mean_ns'] if r['samples'] == 1 else 1)
            self.assertGreaterEqual(r['queue_depth_observed_max'], 1)
            self.assertEqual(r['errors'], 0)
            devices[r['device']] = devices.get(r['device'], 0) + r['bytes']
        self.assertTrue(any(total == 64 * 65536 for total in devices.values()), devices)
        self.assertEqual(rows[-1]['active_requests'], 0)
        self.report(path, 'IO_JITTER')
        print('IO bytes per device:', devices)
        filename.unlink()

    def test_memory_faults_mmap_failure_rss(self):
        child, _ = self.workload('mem')
        monitor, path = self.monitor('mem_pressure', 5, '--pid', str(child.pid), '--baseline-faults', '100')
        child.stdin.write('g\n'); child.stdin.flush()
        self.assertEqual(child.wait(timeout=8), 0, child.stderr.read())
        rows = self.finish(monitor, path)
        metrics = [r for r in rows if r['event'] == 'mem_metric']
        self.assertGreaterEqual(sum(r['faults'] for r in metrics), 8192)
        self.assertEqual(sum(r['large_mmap_calls'] for r in metrics), 3)
        self.assertEqual(sum(r['large_mmap_failures'] for r in metrics), 1)
        self.assertTrue(all(r['pid'] == child.pid and r['addr'].startswith('0x') for r in metrics))
        valid = [r for r in metrics if r['rss_valid']]
        self.assertTrue(valid)
        self.assertTrue(any(r['rss_bytes'] >= 32 << 20 for r in valid))
        self.assertTrue(any(r['rss_growth_valid'] and r['rss_growth_bytes_per_sec'] > 0 for r in valid))
        self.report(path, 'MEM_PRESSURE')
        print('MEM faults:', sum(r['faults'] for r in metrics))

    def test_lock_timeouts_eagain_stacks_and_cleanup(self):
        child, identity = self.workload('lock')
        monitor, path = self.monitor('lock_contention', 3, '--pid', str(child.pid), '--histogram')
        child.stdin.write('g\n'); child.stdin.flush()
        self.assertEqual(child.wait(timeout=6), 0, child.stderr.read())
        rows = self.finish(monitor, path)
        metrics = [r for r in rows if r['event'] == 'lock_metric']
        waits = [r for r in metrics if int(r['uaddr'], 16) == int(identity['lock'], 16)]
        self.assertTrue(waits)
        self.assertEqual({r['op'] for r in waits}, {0, 9})
        self.assertEqual(sum(r['samples'] for r in waits), 24)
        self.assertEqual(sum(r['timeouts'] for r in waits), 24)
        self.assertGreaterEqual(max(r['waiter_count'] for r in waits), 4)
        self.assertGreater(sum(r['offcpu_ns_total'] for r in waits), 500_000_000)
        self.assertTrue(any(r['stacks'] and any(s['available'] and s['frames'] for s in r['stacks']) for r in waits))
        for r in waits:
            self.assertEqual(sum(r['latency_buckets']), r['samples'])
            self.assertLessEqual(r['offcpu_ns_total'], r['wait_ns_total'])
        failures = [r for r in metrics if int(r['uaddr'], 16) == int(identity['mismatch'], 16)]
        self.assertEqual(sum(r['eagain'] for r in failures), 10)
        self.assertEqual(sum(r['samples'] for r in failures), 0)
        self.assertFalse(any(r.get('type') == 'LOCK_CONTENTION' and r['key_metrics']['uaddr'] == identity['mismatch'] for r in rows))
        self.assertEqual(rows[-1]['active_waits'], 0)
        self.report(path, 'LOCK_CONTENTION')
        report = json.loads(path.with_suffix('.report.json').read_text())
        self.assertTrue(any(a['type'] == 'LOCK_CONTENTION' and a['key_metrics']['stacks'] for a in report['anomalies']))
        print('LOCK completed WAIT/WAIT_BITSET=24 EAGAIN=10')

    def test_oom_private_cgroup_victim(self):
        base = Path('/sys/fs/cgroup/memory')
        if not (base / 'memory.limit_in_bytes').exists():
            self.skipTest('需要可写的 memory cgroup v1；未验证不能声称 OOM 通过')
        group = base / f'osmedic-stage2-{os.getpid()}'
        try:
            group.mkdir()
        except OSError as exc:
            self.skipTest(f'无法创建隔离 cgroup：{exc}')
        child = None
        try:
            (group / 'memory.limit_in_bytes').write_text(str(32 << 20))
            if (group / 'memory.memsw.limit_in_bytes').exists():
                (group / 'memory.memsw.limit_in_bytes').write_text(str(32 << 20))
            self.assertEqual((group / 'tasks').read_text().strip(), '')
            child, _ = self.workload('oom')
            (group / 'tasks').write_text(str(child.pid))
            monitor, path = self.monitor('mem_pressure', 4, '--pid', str(child.pid))
            child.stdin.write('g\n'); child.stdin.flush()
            self.assertEqual(child.wait(timeout=8), -signal.SIGKILL, '只有测试子进程应被私有32MiB限制杀死')
            rows = self.finish(monitor, path)
            victims = [r for r in rows if r.get('type') == 'OOM_KILL']
            self.assertTrue(victims)
            self.assertTrue(all(r['pid'] == child.pid and r['key_metrics']['victim_pid'] == child.pid for r in victims))
            self.assertTrue(all(r['key_metrics']['identity_known'] is False for r in victims))
            self.report(path, 'OOM_KILL')
            print('OOM isolated victim:', child.pid)
        finally:
            if child is not None:
                self.stop_process(child)
            group.rmdir()

    def test_sigint_clean_exit(self):
        for binary in BINARIES:
            monitor, path = self.monitor(binary, 30)
            monitor.send_signal(signal.SIGINT)
            self.finish(monitor, path, allow_empty=True)

    def test_high_thresholds_do_not_fabricate_diagnoses(self):
        cases = [('io', 'io_latency', ['--baseline-p99-us', '1000000000'], 2),
                 ('mem', 'mem_pressure', ['--baseline-faults', '1000000000'], 4),
                 ('lock', 'lock_contention', ['--min-waiters', '100', '--wait-ms', '1000000000'], 2)]
        for mode, binary, flags, seconds in cases:
            with self.subTest(scene=mode):
                extra = [self.artifacts / 'negative-io.img'] if mode == 'io' else []
                child, _ = self.workload(mode, *extra)
                monitor, path = self.monitor(binary, seconds, '--pid', str(child.pid), *flags)
                child.stdin.write('g\n'); child.stdin.flush()
                self.assertEqual(child.wait(timeout=8), 0, child.stderr.read())
                rows = self.finish(monitor, path)
                self.assertTrue(any(r['event'].endswith('_metric') for r in rows))
                self.assertFalse(any(r['event'] == 'diagnosis' for r in rows))
                for file in extra:
                    file.unlink()

    def test_fault_scripts_bounded_and_cleanup(self):
        directory = self.artifacts / 'fio-temp'
        directory.mkdir()
        env = dict(os.environ, OSMEDIC_IO_DIR=str(directory))
        for script in ['03_io.sh', '04_mem.sh', '05_lock.sh']:
            for argument in ['0', '-1', 'bad']:
                result = subprocess.run(['bash', str(ROOT / 'faults' / script), argument], capture_output=True)
                self.assertEqual(result.returncode, 1)
            with (self.artifacts / (script + '.log')).open('w') as log:
                result = subprocess.run(['bash', str(ROOT / 'faults' / script), '1'], stdout=log, stderr=log, env=env, timeout=12)
                self.assertEqual(result.returncode, 0, script)
        self.assertEqual(list(directory.iterdir()), [], 'fio临时文件必须清理')


if __name__ == '__main__':
    unittest.main(verbosity=2)
