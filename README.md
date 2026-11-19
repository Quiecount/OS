# 太卡了先生：基于 eBPF 的 openEuler 系统异常观测与根因定位工具

> 全国大学生计算机系统能力大赛 · 操作系统设计赛（华东区域赛）· 操作系统应用开发赛道
> 运行环境：openEuler 24.03 LTS（内核 6.6） · 代码工作代号：osmedic

---

## 报名信息

> 按大赛提交要求注明

| 项 | 内容 |
|---|---|
| GitLab 项目名称（选题方向-自定义名称） | **系统工具-太卡了先生** |
| 高校名称 | 杭州电子科技大学 |
| 队伍ID | T2026103369913109 |
| 队伍名称 | 太卡了先生 |

---

## 题目内容

随着云、边、端技术的融合发展，操作系统面临复杂多变的业务负载，传统的日志分析和静态监控手段难以应对高频、瞬时的系统性能异常。eBPF 凭借其低侵入、高效率的特性，成为解决系统底层故障诊断、实时观测难题的关键技术。

本作品基于 eBPF，在 openEuler 24.03 LTS 上构建一套**轻量级、高实时性**的系统异常观测与根因定位工具，实现：

- 面向 **5 类典型异常场景**完成观测与诊断：
  1. **CPU 异常占用 / 调度延迟**——找出谁在持续吃满 CPU、谁在等待调度
  2. **I/O 延迟抖动 / 阻塞等待**——定位热点文件、设备或队列拥堵
  3. **内存抖动 / OOM 风险**——识别大块内存申请、回收压力与缺页激增
  4. **锁竞争导致性能退化**——发现热点锁、等待线程和吞吐下降原因
  5. **高频 / 高耗时系统调用热点**——识别 syscall 热点与异常行为来源
- **结构化诊断结果**：输出包含异常类型、关联对象、关键指标、异常时间窗口、疑似根因、证据链、建议性结论的 JSON 诊断报告，便于机器解析与自动评测
- **根因定位**：能定位关键进程 / 线程 / 系统调用 / 资源对象
- **低开销**：eBPF 内核探针逐条采集，附加开销受控，生产环境可常开
- **智能可读**（创新点）：规则引擎产出确定性诊断后，由 LLM 将结构化证据翻译为人类可读的根因分析与优化建议——AI 不参与判断，只参与表达

---

## 系统架构

```
eBPF 探针层 ──► 采集代理 ──► 聚合与特征层 ──► 规则诊断引擎 ──► JSON 诊断报告
（内核态）        （用户态）    （系统画像/基线）    （根因+证据链）        │
                                                                          ▼
                                                                  LLM 可读报告（差异化亮点）
```

设计原则：**准确性靠规则引擎**（确定性逻辑，误报/漏报可控），**可读性靠 LLM**（只做解释层，喂结构化证据）。

## 仓库结构

```
AGENTS.md           # 仓库协作规范（团队成员与 AI 编程助手必读）
docs/
├── 华东区域赛应用开发赛道选题分析.md    # 选题调研：历届作品盘点与选题决策
├── 开发计划_eBPF异常观测与根因定位工具.md # 8.5 周分阶段开发计划（含验收标准/砍单指南）
├── 系统设计_五场景总体框架.md           # 总体架构：五层流水线 / 事件契约 / 场景填肉清单
├── 开发指南_第一支探针execsnoop.md      # 探针① execsnoop：原理走读 + 构建运行 + 排错
└── 团队开发环境搭建指南.md              # 开发环境：各自本机 Hyper-V 虚拟机为主，云虚拟机备选
src/                # 探针（probes/ 6 个：execsnoop 完整 + 5 场景骨架）/ 加载器 / 事件契约 events.h
analysis/           # 聚合与规则引擎（骨架：collector.py，阶段 3 完成规则）
report/             # LLM 报告层（阶段 4 建，带 --no-llm 降级开关）
faults/             # 五场景故障注入（01-05 脚本 + syscall_bomb / lock_contention 程序）
tests/              # 一键回归测试（骨架：test.sh，阶段 3 接入自动判定）
deploy.sh           # 一键部署（依赖安装 + 编译）
test.sh             # 一键测试入口（转调 tests/test.sh）
```

## 开发计划

| 阶段 | 内容 | 状态 |
|---|---|---|
| 0 | 环境搭建 + 第一支探针 | yu 的 minimal 已验收；其余环境清单待逐项确认 |
| 1 | libbpf 探针基础 | :construction: exec/ringbuf 与 IO/map/JSON Lines 已验证，待全员独立复现 |
| 2 | 五场景逐个攻坚 | :construction: execsnoop 契约迁移已验证；五场景指标继续实现 |
| 3 | 诊断引擎 + 结构化输出 | :hourglass: 待开始 |
| 4 | LLM 报告层 | :hourglass: 待开始 |
| 5 | 性能开销评测 + 一键复现 + 文档 + 视频 | :hourglass: 待开始 |

详见 [docs/开发计划_eBPF异常观测与根因定位工具.md](docs/开发计划_eBPF异常观测与根因定位工具.md)。

## 环境要求与快速验证

- openEuler 24.03 LTS（内核 6.6，原生支持 eBPF）
- 工具链：`dnf install -y bpftrace bcc-tools libbpf-devel clang llvm make git stress-ng fio sysstat kernel-devel`

一条命令验证（eBPF 版 Hello World，实时观察内核事件流）：

```bash
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
```

已将阶段 0 的 libbpf-bootstrap minimal 学习示例整理到 `src/probes/` 和
`src/loader/`，构建入口为 `make -C src`。依赖安装、运行与代码来源见
[ebpf-learning 迁入说明](docs/ebpf-learning迁入说明.md)。

阶段 1 已实现成功 exec 事件采集：

```bash
# 构建依赖同迁入说明；产物位于 src/.output/。
make -C src exec_trace
sudo ./src/.output/exec_trace -o /tmp/osmedic-exec.jsonl
# 在另一终端执行 /usr/bin/true 等程序；Ctrl+C 停止采集。
```

用法、事件字段、权限要求与验证记录见
[阶段 1：进程启动事件与 JSON Lines](docs/阶段1_exec追踪与JSONL.md)。

阶段 1 的块设备 IO 延迟直方图也已实现：

```bash
make -C src io_latency
# 每秒输出读、写累计直方图，共输出 5 组快照。
sudo ./src/.output/io_latency -i 1 -n 5 -o /tmp/osmedic-io.jsonl
```

设备过滤、直方图含义与真实 IO 验证见
[阶段 1：块设备 IO 延迟直方图](docs/阶段1_IO延迟直方图.md)。

GitLab 主干的 execsnoop 已按[接口契约](docs/接口契约.md)迁移为默认 JSON Lines：

```bash
make check
sudo ./build/execsnoop --duration 5 > /tmp/execsnoop.jsonl
python3 analysis/collector.py --input /tmp/execsnoop.jsonl
# 人工查看表格时：sudo ./build/execsnoop --duration 5 --pretty
```

新旧实现的区分、工具链参数和本次验收见
[GitLab 同步与 execsnoop 契约迁移](docs/GitLab同步与execsnoop契约迁移.md)。

## 演示视频

:construction: 提交前在此补充链接。

## 说明

- educg GitLab 为比赛官方仓（HTTPS，必推）；GitHub 为尽力同步的镜像
- yu 在 `dev/yu` 开发和推送；main 合并与发布由 owner 执行
- 开发过程开源，提交记录即过程性资料
