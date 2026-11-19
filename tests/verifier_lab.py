"""在忽略的 build/ 中生成教学样例，比较拒绝日志与修复版的加载结果。"""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PRELUDE = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
char LICENSE[] SEC("license") = "GPL";
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} values SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");
SEC("tp/syscalls/sys_enter_write")
int exercise(void *ctx)
{
"""

CASES = [
    {
        "name": "map_null",
        "reason": r"invalid mem access.*map_value_or_null",
        "broken": "__u32 key = 0; __u64 *value = bpf_map_lookup_elem(&values, &key); return *value;",
        "fixed": "__u32 key = 0; __u64 *value = bpf_map_lookup_elem(&values, &key); return value ? *value : 0;",
        "explanation": "map 查找可能返回 NULL，解引用前必须判空。",
    },
    {
        "name": "map_bounds",
        "reason": r"invalid access to map value|invalid access to map",
        "broken": "__u32 key = 0; __u64 *value = bpf_map_lookup_elem(&values, &key); if (!value) return 0; return value[1];",
        "fixed": "__u32 key = 0; __u64 *value = bpf_map_lookup_elem(&values, &key); if (!value) return 0; return value[0];",
        "explanation": "value 只有 8 字节，第二个 u64 已经越界；判空不能替代边界检查。",
    },
    {
        "name": "ringbuf_release",
        "reason": r"unreleased reference",
        "broken": "void *record = bpf_ringbuf_reserve(&events, 8, 0); if (!record) return 0; return 1;",
        "fixed": "void *record = bpf_ringbuf_reserve(&events, 8, 0); if (!record) return 0; bpf_ringbuf_discard(record, 0); return 0;",
        "explanation": "reserve 成功后，每条返回路径都必须 submit 或 discard 释放记录。",
    },
]


def run_lab(output, clang="clang", loader=None):
    loader = loader or ROOT / "build/verifier_lab"
    if os.geteuid() != 0:
        raise RuntimeError("Verifier 实验需要 root；未授权不算预期拒绝")
    if not loader.is_file():
        raise RuntimeError("缺少实验加载器；先执行 make build/verifier_lab")
    flags = shlex.split(os.environ.get("LIBBPF_CFLAGS", ""))
    if not flags:
        flags = shlex.split(subprocess.check_output(
            ["pkg-config", "--cflags", "libbpf"], text=True))
    output.mkdir(parents=True, exist_ok=True)
    report = {"status": "FAIL", "attached": False, "cases": []}
    try:
        for case in CASES:
            result = {"name": case["name"], "explanation": case["explanation"]}
            for version in ["broken", "fixed"]:
                name = f'{case["name"]}_{version}'
                source = output / (name + ".bpf.c")
                obj = output / (name + ".bpf.o")
                source.write_text(PRELUDE + case[version] + "\n}\n")
                compilation = subprocess.run(
                    [clang, "-O2", "-g", "-target", "bpf", *flags, "-c", str(source), "-o", str(obj)],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                )
                (output / (name + ".compile.log")).write_bytes(compilation.stdout)
                if compilation.returncode:
                    raise RuntimeError(f"{name}: 编译失败，不能计为 Verifier 拒绝")
                loaded = subprocess.run([str(loader), str(obj)], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=15)
                log = loaded.stderr.decode(errors="replace")
                (output / (name + ".verifier.log")).write_text(log)
                result[version + "_exit_code"] = loaded.returncode
                if version == "broken":
                    if loaded.returncode != 1 or b"VERIFIER_REJECTED" not in loaded.stdout:
                        raise RuntimeError(f"{name}: 未出现预期内核拒绝")
                    match = re.search(case["reason"], log, re.I)
                    if not match:
                        raise RuntimeError(f"{name}: 拒绝原因不匹配，查看日志；权限失败不能算通过")
                    result["diagnostic"] = next(line.strip() for line in log.splitlines()
                                                if re.search(case["reason"], line, re.I))
                elif loaded.returncode != 0 or b"VERIFIER_ACCEPTED" not in loaded.stdout:
                    raise RuntimeError(f"{name}: 修复版未通过内核加载")
            result["status"] = "PASS"
            report["cases"].append(result)
            print(f'[{case["name"]}] expected rejection + fixed load PASS')
        report["status"] = "PASS"
        return report
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    base = ROOT / "build"
    base.mkdir(exist_ok=True)
    output = args.output or Path(tempfile.mkdtemp(prefix="verifier-", dir=base))
    # 实验中的错误代码和对象只允许生成在被忽略的构建目录。
    output = output.resolve()
    if not output.is_relative_to(base.resolve()):
        parser.error("--output 必须位于 build/ 内")
    try:
        run_lab(output, clang=os.environ.get("CLANG", "clang"))
    except Exception as error:
        print(f"VERIFIER_LAB_FAIL: {error}; logs={output}", file=sys.stderr)
        return 1
    print(f"VERIFIER_LAB_PASS: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
