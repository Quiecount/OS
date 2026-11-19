# 阶段 1：块设备 IO 延迟直方图与 map 输出

## 本次完成范围

在 `dev/yu` 实现开发计划 §五阶段 1 的第二支探针：块请求 issue → complete
计时、map 累计直方图、用户态读取并输出 JSON Lines。
本次验证环境为 openEuler 24.03 LTS、内核
`6.6.0-28.0.0.34.oe2403.x86_64`，底层请求设备为 `sda`（`8:0`）。

| 文件 | 用途 |
|---|---|
| `src/probes/io_latency_learning.bpf.c` | 关联请求、记录完成延迟、处理部分完成和重入队 |
| `src/probes/io_latency.h` | 共享 map 结构、直方图桶及完成判定 |
| `src/loader/io_latency_learning.c` | 设备过滤参数、周期读取 map、JSON Lines 与资源回收 |
| `tests/test_io_latency_math.c` | 桶边界、饱和及部分完成判定测试，无需 BPF 权限 |
| `tests/test_io_latency.py` | 真实内核加载与普通文件直接读写集成测试 |

本次只完成采集基础。正式场景 3 的设备/进程关联、IOPS、队列深度、异常规则和
故障注入仍按阶段 2/3 推进。阶段 1 的全员独立复现尚未完成。
`AGENTS.md` 的阶段 0 状态仍需 owner 根据开发计划同步更新。

## 计时与关联方法

本机 BTF 确认以下原始 tracepoint 参数存在，探针以 `tp_btf` 挂载同名 block 事件：

- `block_rq_issue(struct request *)`：记录本次下发时间、剩余请求字节数和读/写类型。
- `block_rq_complete(struct request *, blk_status_t, unsigned int)`：找到同一请求，
  在最后一段完成时更新直方图并删除计时项。
- `block_rq_requeue(struct request *)`：删除旧计时，后续 issue 重新开始计时。

使用 `request *` 作为关联键，避免仅按扇区号关联时把并发请求混在一起。
计时项存于容量 32768 的 hash map；容量耗尽等写入失败累加 `tracking_failures`。
仅统计非零字节的读/写请求，flush、discard 等其他操作不纳入直方图。

Linux 6.6 的 `block_rq_complete` 可以表示部分完成，且触发点位于
`rq->__data_len` 更新之前。因此有 bio 且 `nr_bytes < __data_len` 时保留计时，
继续等待最后一段；任一段出错会让最终样本的错误计数增加一次。
依据：[Linux 6.6 block 事件定义](https://github.com/torvalds/linux/blob/v6.6/include/trace/events/block.h)、
[blk_update_request / blk_complete_request 调用位置](https://github.com/torvalds/linux/blob/v6.6/block/blk-mq.c)。

测量范围是“最后一次 issue 到最后一段 complete”的单调时钟延迟。
重入队之前的尝试和两次下发之间的排队时间不计入该范围；它不是应用层读写耗时。
请求合并、拆分、文件系统元数据和设备映射也使请求数与应用系统调用数不同。

直方图按读、写分别存入 per-CPU array map，使用原子加法累计桶数、字节数、
延迟总和与错误数。用户态按 possible CPU 数分配对齐缓冲并求和，
布局与并发处理依据[内核 array/per-CPU map 文档](https://docs.kernel.org/bpf/map_array.html)。
probe 无循环，计时结构在栈上，完整直方图直接在 map 内更新。

## 构建和使用

系统工具链依赖与 exec 示例一致，见[学习目录迁入说明](ebpf-learning迁入说明.md)。

```bash
make -C src io_latency

# 每秒输出一次，共输出 5 组快照；一组包含 read / write 两行。
sudo ./src/.output/io_latency -i 1 -n 5 -o /tmp/osmedic-io.jsonl

# 持续采集指定整盘的请求，Ctrl+C 结束。
lsblk -o NAME,MAJ:MIN,TYPE,MOUNTPOINTS
sudo ./src/.output/io_latency -d 8:0
```

本机复验仍复用原学习目录工具链：

```bash
make -C src io_latency \
  BPFTOOL=/root/ebpf-learning/libbpf-bootstrap/examples/c/.output/bpftool/bootstrap/bpftool \
  LIBBPF_CFLAGS=-I/root/ebpf-learning/libbpf-bootstrap/examples/c/.output \
  LIBBPF_LIBS='/root/ebpf-learning/libbpf-bootstrap/examples/c/.output/libbpf.a -lelf -lz'
```

| 参数 | 含义 |
|---|---|
| `-d MAJOR:MINOR` / `--device` | 按请求队列的整盘设备号过滤，默认汇总所有设备 |
| `-i SECONDS` / `--interval` | 正整数秒，1..3600，默认 1 |
| `-n COUNT` / `--count` | 正整数快照组数，1..1000000；省略则持续采集 |
| `-o FILE` / `--output` | 追加 JSON Lines；默认 stdout，`-o -` 亦为 stdout |
| `-v` / `--verbose` | stderr 输出 libbpf 调试日志 |
| `-h` / `--help` | 帮助，无需 BPF 权限 |

`-d` 使用请求队列 `gendisk` 的 major / first_minor。本机文件系统位于
device-mapper 卷，底层是 sda3，但实际请求设备为 sda，所以使用 `8:0`，
而不是分区号或逻辑卷号。默认汇总模式可能包含多层设备观测到的请求，不能据此
推导唯一物理 IO 数。其他内核、堆叠设备及架构均需另行验证。

输出父目录必须已存在。打开、写入或关闭失败会返回非零状态；日志与统计写 stderr。
SIGINT / SIGTERM 会提前结束等待，解除挂载并输出最终快照；
采集结束时尚未完成的请求不计入直方图，会作为 `unfinished` 报告。

## JSON Lines 与桶含义

以下为格式示例，时间和延迟数字用于展示字段：

```json
{"event":"block_io_latency","clock":"monotonic","window":{"start_ns":1000000000,"end_ns":2000000000},"cumulative":true,"final":true,"device":{"major":8,"minor":0},"operation":"read","requests":8,"bytes":524288,"latency_total_ns":1200000,"errors":0,"bucket_scale":"log2_us","histogram":[0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
```

- `window.start_ns/end_ns` 为 `CLOCK_MONOTONIC` 纳秒时间，覆盖从采集开始到本次读取。
- `cumulative` 固定为 true。快照为累计值，不可把各行直接相加。
  同一次采集的相邻同类快照可求差，近似得到该间隔内完成的请求数据。
- `final` 为 true 表示解除挂载后的最终快照；达到 `-n` 指定次数时，最后一组为最终快照。
- `device` 在不使用过滤时为 null；使用过滤时为指定整盘的 major/minor。
- `requests` 为所有桶计数之和；`bytes` 为已完成样本在本次 issue 时的请求字节数之和。
- `latency_total_ns` 是这些样本的延迟总和；非空时除以 requests 得到平均延迟。
- `errors` 为至少有一段以错误状态完成的请求数；出错请求仍计入总数和延迟。

桶索引由 `floor(log2(latency_ns / 1000))` 计算，0 微秒归入首桶，超出范围饱和：

| 索引 | 延迟范围（微秒） |
|---|---|
| 0 | `[0, 2)` |
| 1 | `[2, 4)` |
| 2 | `[4, 8)` |
| 3..30 | `[2^i, 2^(i+1))` |
| 31 | `[2^31, +∞)` |

在线读取 per-CPU map 时，内核可能同时更新其他字段或其他 CPU，快照不是跨 CPU、
跨字段的事务一致视图；最终快照在解除挂载后读取，可用于核对桶与总量。
这一版不清空 map，避免读取/清零与内核更新竞争导致丢计。
`fflush` 只刷新用户态缓冲，不提供断电持久化或多个采集器共用文件的协调。

stderr 最终打印：`tracking_failures=N partial_completions=N requeued_requests=N unfinished=N`。
这些计数只针对纳入跟踪的读写请求；缺少起始记录的完成事件会被忽略。
其中部分完成表示中间完成通知数，重入队表示被取消计时的下发尝试数。

## 测试与验收结果（2026-11-18）

```bash
# 无需 root：对数桶边界和部分完成判定。
make -C src check-io-math

# 需要 BPF 权限：真实内核与直接 IO 验证。
sudo python3 tests/test_io_latency.py
```

本机 C 数学边界测试 PASS，5 项内核集成测试全部 PASS：

- 帮助与非法设备号、周期、次数参数校验。
- 整盘设备过滤下，直接读写的延迟、桶计数、字节数与 SIGINT 最终快照。
- 不匹配设备过滤后，真实 IO 不进入直方图。
- 周期累计快照、固定次数退出、文件追加、JSON 与日志分流。
- `/dev/full` 写入失败返回非零状态。

定量用例对构建目录内新建的普通文件执行 8 次 64 KiB 直接写，再执行相同规模的直接读，
捕获 `8:0` 上的 read=8 次、524288 字节，write=10 次、573440 字节。
写入还包括文件系统产生的请求，因此写请求总量超过测试数据本身是预期现象。
测试未向原始块设备写入，未修改全局缓存或设备设置；临时文件已清理。
`/tmp` 在本机是 tmpfs，测试特意使用被 Git 忽略的 `src/.output/` 内普通文件。

最终直方图总量、延迟桶给出的总延迟范围均通过断言，`tracking_failures=0`。
真实硬件错误、部分完成、重入队及 map 耗尽的内核路径尚未人工注入验证；
部分完成分支已有纯函数边界测试。高负载开销、长期运行与跨内核适配仍待评测。

阶段 1 的两条代码链路现已具备：exec → ringbuf → JSON Lines，以及
IO issue/complete → map → JSON Lines。队员独立复现与 Verifier 学习验收后，
下一步按阶段 2 的顺序实现 syscall 热点场景。

## GitLab 框架同步（2026-11-19）

为保留双方实现，学习版探针源文件迁为 `io_latency_learning.bpf.c`，加载器迁为
`src/loader/io_latency_learning.c`，
`make -C src io_latency` 和加载器路径保持不变。
`src/probes/io_latency.bpf.c` 保留 GitLab 场景 3 框架，使用冻结的 `src/events.h`。
学习版累计 map 快照用于阶段 1 验证；阶段 2 的输出以 `docs/接口契约.md` 为准。
