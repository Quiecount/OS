"""阶段 1 工程验收：重建、真实内核测试、Verifier 实验、证据归档。"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


class StepFailure(RuntimeError):
    def __init__(self, result):
        self.result = result
        super().__init__(f'{result["name"]} failed; see {result["log"]}')


def run_step(name, command, output, cwd=ROOT, timeout=180):
    log = output / (name + ".log")
    result = {"name": name, "command": command, "log": log.name, "status": "FAIL"}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", LC_ALL="C", TZ="Asia/Shanghai")
    try:
        with log.open("wb") as stream:
            completed = subprocess.run(command, cwd=cwd, stdout=stream,
                                       stderr=subprocess.STDOUT, env=env, timeout=timeout)
        result["exit_code"] = completed.returncode
    except (OSError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)
        raise StepFailure(result) from error
    if completed.returncode:
        raise StepFailure(result)
    result["status"] = "PASS"
    return result


def finish_report(report, succeeded):
    # 自动化执行永远不替成员填写“独立完成”和评审结果。
    report["engineering_status"] = "PASS" if succeeded else "FAIL"
    report["human_acceptance"] = "PENDING"
    report["phase1_status"] = "PENDING_HUMAN" if succeeded else "ENGINEERING_FAILED"
    return report


def check_environment():
    distribution = platform.freedesktop_os_release()
    kernel = platform.release()
    if distribution.get("ID", "").lower() != "openeuler" or distribution.get("VERSION_ID") != "24.03":
        raise RuntimeError("本阶段验收要求 openEuler 24.03")
    if not kernel.startswith("6.6.") or platform.machine() != "x86_64":
        raise RuntimeError("本阶段实测目标为内核 6.6 / x86_64")
    if os.geteuid() != 0:
        raise RuntimeError("请在目标虚拟机中使用 sudo；权限失败不能视为 Verifier 实验通过")
    if not Path("/sys/kernel/btf/vmlinux").is_file():
        raise RuntimeError("缺少运行内核 BTF")
    for tool in ["make", "cc", "clang", "bpftool", "pkg-config"]:
        if not shutil.which(tool):
            raise RuntimeError(f"缺少 {tool}，请先按阶段 1 验收指南准备系统工具链")
    libbpf = subprocess.check_output(["pkg-config", "--modversion", "libbpf"], text=True).strip()
    return {
        "distribution": distribution.get("PRETTY_NAME"), "kernel": kernel,
        "architecture": platform.machine(), "libbpf": libbpf,
        "bpftool": subprocess.check_output(["bpftool", "version"], text=True).splitlines()[0],
        "clang": subprocess.check_output(["clang", "--version"], text=True).splitlines()[0],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator", default="automation", help="执行者标签，不代表独立复现已验收")
    args = parser.parse_args()
    base = ROOT / "build/stage1-evidence"
    base.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone(timedelta(hours=8)))
    output = Path(tempfile.mkdtemp(prefix=now.strftime("%Y%m%d-%H%M%S-"), dir=base))
    report = {
        "recorded_at": now.isoformat(), "operator_label": args.operator,
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "working_tree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "steps": [], "source_sha256": {},
    }
    succeeded = False
    try:
        report["environment"] = check_environment()
        for relative in [
            "Makefile", "src/Makefile", "src/events.h", "src/probes/execsnoop.bpf.c",
            "src/probes/exec_trace.bpf.c", "src/probes/io_latency_learning.bpf.c",
            "src/loader/execsnoop.c", "src/loader/exec_trace.c", "src/loader/io_latency_learning.c",
            "src/loader/verifier_lab.c", "tests/stage1_acceptance.py", "tests/verifier_lab.py",
        ]:
            report["source_sha256"][relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        steps = [
            ("build", ["make", "--always-make", "check", "build/verifier_lab"]),
            ("learning_build", ["make", "--always-make", "-C", "src", "all"]),
            ("integration", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"]),
            ("verifier", [sys.executable, "tests/verifier_lab.py", "--output", str(output / "verifier")]),
        ]
        for name, command in steps:
            try:
                result = run_step(name, command, output)
            except StepFailure as error:
                report["steps"].append(error.result)
                raise
            report["steps"].append(result)
            print(f"[{name}] PASS", flush=True)
        report["verifier"] = json.loads((output / "verifier/report.json").read_text())
        succeeded = True
    except Exception as error:
        report["error"] = str(error)
        print(f"STAGE1_ENGINEERING_FAIL: {error}", file=sys.stderr)
    finally:
        finish_report(report, succeeded)
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(f"Evidence: {output}")
    if succeeded:
        print("STAGE1_ENGINEERING_PASS; human acceptance remains PENDING")
    return 0 if succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
