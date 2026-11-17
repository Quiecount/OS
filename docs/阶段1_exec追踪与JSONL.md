# 阶段 1：进程启动事件 → ringbuf → JSON Lines

## 本次完成范围

按开发计划 §五阶段 1 实现首支进程启动探针，并把采集事件写成 JSON Lines。
本次在 `dev/yu` 开发，运行环境为 openEuler 24.03 LTS、
`6.6.0-28.0.0.34.oe2403.x86_64`。

阶段 0 的 minimal 已通过本机复验；完整工具包清单、bpftrace 学习清单和
全员验收仍需逐项确认。`AGENTS.md` 当前阶段仍写阶段 0，需 owner 同步状态。
本次推进以开发计划的阶段 1 任务和实际验收记录为依据。

| 文件 | 职责 |
|---|---|
| `src/probes/exec_trace.bpf.c` | 成功 exec 事件采集、PID 过滤、ringbuf 提交、丢失计数 |
| `src/probes/exec_trace.h` | 内核态与用户态共享的定长事件结构 |
| `src/loader/exec_trace.c` | 配置、加载、事件消费、JSON 转义、输出、信号退出与资源回收 |
| `src/Makefile` | 从本机 BTF 生成 vmlinux.h，编译探针并生成 skeleton 和加载器 |
| `tests/test_exec_trace.py` | 在真实内核上验证事件与输出行为 |

## 采集过程与挂载点

1. 用户态打开 skeleton，设置 `target_pid`，然后加载探针。
2. 挂载 `sched:sched_process_exec`。本机实测 format 中存在 filename、pid 和 old_pid。
3. 内核在 exec 成功后触发事件。探针直接在 ringbuf 预留事件空间，读取当前任务
   PID、父 PID、UID、comm 和执行路径，提交事件。
4. 用户态 `ring_buffer__poll` 消费记录，每条写一行 JSON 并刷新文件缓冲。
5. SIGINT / SIGTERM 触发退出：先解除挂载，消费已入队事件，再释放资源并关闭文件。

这里的“启动”指程序映像被成功执行，包括 execve / execveat。
失败的 exec 不产生事件；单独 fork 而没有 exec 不产生事件；同一 PID 多次 exec
会产生多条记录。它与 minimal 只追踪加载器自身 write 的行为不同。

`task_struct` 和 tracepoint 上下文字段通过 BTF / CO-RE 读取；filename 的
`__data_loc` 低 16 位提供字符串相对上下文的偏移，使用 helper 读取定长路径。
完整事件直接写入 ringbuf，避免把路径数组放在 BPF 栈上。
ringbuf 容量为 256 KiB；预留失败时累加 `dropped_events`。
此处理遵循[内核 ringbuf 文档](https://docs.kernel.org/bpf/ringbuf.html)规定的
非阻塞预留与提交方式。用户态接口参考
[libbpf API 文档](https://libbpf.readthedocs.io/en/latest/api.html)。

探针改造参考本机 libbpf-bootstrap 的 bootstrap 示例，保留相应版权声明；
版本及许可见 [libbpf-bootstrap 版权说明](licenses/libbpf-bootstrap.md)。

## 构建与复现

从 OS 根目录开始，系统工具链方式：

```bash
sudo dnf install -y clang llvm gcc make pkgconf-pkg-config libbpf-devel bpftool
make -C src

# 终端一：以追加方式写入临时采集文件。
sudo ./src/.output/exec_trace -o /tmp/osmedic-exec.jsonl

# 终端二：制造一次很快结束的成功 exec。
/usr/bin/true

# 终端一 Ctrl+C 后，查看 JSON Lines。
python3 -c 'import json; print([json.loads(s) for s in open("/tmp/osmedic-exec.jsonl")][-3:])'
```

若本机使用原学习目录中已经编译好的工具链：

```bash
make -C src \
  BPFTOOL=/root/ebpf-learning/libbpf-bootstrap/examples/c/.output/bpftool/bootstrap/bpftool \
  LIBBPF_CFLAGS=-I/root/ebpf-learning/libbpf-bootstrap/examples/c/.output \
  LIBBPF_LIBS='/root/ebpf-learning/libbpf-bootstrap/examples/c/.output/libbpf.a -lelf -lz'
```

`VMLINUX_BTF` 默认 `/sys/kernel/btf/vmlinux`，可传入 `make` 指定其他 BTF 文件。
本次复验使用上述原学习目录工具链。系统包方式未在本机复验。
切换工具链或内核时执行 `make -C src clean` 后重建。

| 参数 | 说明 |
|---|---|
| 无参数或 `-o -` | JSON Lines 输出到 stdout |
| `-o FILE` / `--output FILE` | 追加到文件；父目录必须已存在 |
| `-p PID` / `--pid PID` | 只采集这个 TGID 的后续成功 exec，PID 必须为正整数 |
| `-v` / `--verbose` | 在 stderr 输出 libbpf 调试日志 |
| `-h` / `--help` | 查看帮助，无需 BPF 权限 |

日志、就绪提示和退出统计均写 stderr，stdout 保持纯 JSON Lines。
输出文件打开、写入或关闭失败会以非零状态退出；管道断开同样报告失败。
默认采集全系统后续 exec，`-p` 不包含子进程，也不补采历史事件。

## JSON Lines 字段

以下为字段示例，数字用于说明格式：

```json
{"event":"process_exec","timestamp_ns":123456789000,"clock":"monotonic","pid":12345,"ppid":12000,"uid":0,"comm":"true","filename":"/usr/bin/true","filename_truncated":false,"filename_error":false}
```

| 字段 | 含义 |
|---|---|
| `event` | 固定 `process_exec` |
| `timestamp_ns` / `clock` | `bpf_ktime_get_ns()` 的单调时钟纳秒时间，排除系统挂起时间，不能直接当日历时间 |
| `pid` / `ppid` | 当前进程 TGID / 当前实际父进程 TGID |
| `uid` | 内核 helper 返回的真实 UID |
| `comm` | 进程名，最多 15 字节 |
| `filename` | exec 的程序路径字符串，最多 255 字节，不保证为绝对路径 |
| `filename_truncated` | helper 返回值达到 256 字节容量，路径可能被截断；刚好 255 字节也会标记 |
| `filename_error` | 内核读取路径失败；路径可能为空 |

引号、反斜杠、控制字符正确转义，有效 UTF-8 原样保留；非法 UTF-8 字节以
`\u00XX` 表达，避免破坏 JSON 编码。该表达不是任意二进制路径的无歧义编码。
截断也可能发生在 UTF-8 字符中间，需要结合标记判断。

退出时 stderr 输出 `events_written=N ringbuf_dropped=M`。
ringbuf 满时无法保证每次 exec 都被记录；需要关注丢失计数。
文件刷新使用 `fflush`，未提供断电持久化保证或多个采集器共享同一输出文件的协调。

这些是阶段 1 的原始采集事件；开发计划 §四的七字段异常诊断报告在阶段 3 实现。
本次仅验证 openEuler 24.03 / x86_64，其他内核与架构仍待实测。

## 自动验证与本次结果

```bash
sudo python3 tests/test_exec_trace.py
```

2026-11-18 在上述 openEuler 真实内核上运行，6 项全部 PASS：

- 帮助与非法 PID 参数验证。
- 成功 exec 捕获、失败 exec 排除、PID / PPID / UID 对应、文件追加、日志分流。
- PID 过滤与 stdout JSON Lines。
- 引号、反斜杠、换行、中文及非法 UTF-8 文件名的 JSON 输出。
- 超长路径截断标记。
- `/dev/full` 输出失败时以非零状态退出。

成功运行的采集器通过 SIGINT 退出，退出统计中的 ringbuf 丢失数为 0。
这些结果验证了 Verifier 加载、CO-RE 字段读取、tracepoint 挂载、ringbuf 消费和输出链路。
高负载下的丢失率与性能开销尚未评测。

## 接下来如何学习与推进

先按顺序阅读共享事件结构、BPF reserve/submit、用户态 callback 和 poll。
独立解释一次“加载前配置只读变量、为何需要 ringbuf、为何日志写 stderr、
为何 exec 失败不输出”，然后关闭教程重新复现一次。

块设备 IO 延迟直方图及 map 读取输出已完成，见
[IO 设计与验收记录](阶段1_IO延迟直方图.md)。
阶段 1 仍需每位成员独立复现并能解释 Verifier 拒绝原因；随后按阶段 2 顺序推进五类异常场景。
