# GitLab 主干同步与 execsnoop 接口迁移

日期：2026-11-19。开发与提交分支：`dev/yu`，作者：yu。

## 同步依据

GitLab main 的最新读取版本为 `2ea7435`，包含五场景框架和接口契约 v1.0。
本次以 merge 合入个人分支，保留 GitHub 上已经发布的个人提交以及 GitLab 的原始历史。
GitLab main 未被本次操作修改。

已完整阅读最新 `AGENTS.md`、开发计划、系统设计、接口契约和第一支探针开发指南。
最新规定是 GitLab 必推、GitHub 尽力同步；阶段 2/3 的模块接口以接口契约为准，
事件结构只允许尾部追加，默认 JSON Lines、日志到 stderr，并提供 duration / pretty。

合并处理：

- `.gitignore` 同时保留双方的排除项，包括两个构建目录和生成的 vmlinux.h。
- GitLab 的 `src/probes/io_latency.bpf.c` 继续作为正式场景 3 的框架。
- 个人阶段 1 IO 探针和加载器分别命名为 `io_latency_learning.bpf.c`、
  `io_latency_learning.c`，`make -C src io_latency` 和旧产物路径继续可用。
- 接受 GitLab 对公开案例文档的删除与目录调整，保留个人验收记录。

## 本次下一步开发

按照接口契约 §二，完成正式 `execsnoop` 的加载器迁移：

- stdout 默认只有 `scene/ts_ns/pid/uid/comm/filename` 六个字段的 UTF-8 JSON Lines。
- `--duration N` 在 1..86400 秒后退出，省略时持续运行。
- `--pretty` 输出人类可读表格；所有模式下提示和错误均到 stderr。
- JSON 字符串进行边界处理、控制字符转义和 UTF-8 检查；读取未来尾部扩展事件时保留兼容。
- SIGINT/SIGTERM 解除挂载并消费队列尾部，正常退出码为 0；输出失败返回 1。
- 不修改 `src/events.h` 的字段、类型或顺序。

探针补齐 `ev_common.ts_ns`。同时修复六个框架探针把栈变量传给三参数
`bpf_ringbuf_submit` 的编译错误，改用四参数 `bpf_ringbuf_output` 复制到 `events` map。
这只修复数据通路，各场景的指标 TODO 仍保持未完成状态。

execsnoop 追踪 `sys_enter_execve`，记录执行尝试，也包括失败的 exec。
`comm` 为调用时的进程名。个人阶段 1 的 `exec_trace` 追踪成功 exec，二者语义不同。
128 字节路径字段来自冻结契约，长路径仍会截断；本次未追加截断标记或失败统计字段。

## 构建和验证

根目录 `make` 构建正式框架、execsnoop 和故障注入程序；`make -C src` 构建个人学习示例。
根目录 Makefile 增加 BPFTOOL / LIBBPF_CFLAGS / LIBBPF_LIBS 覆盖参数、头文件依赖跟踪和
`make check`，从而可以使用系统工具链，也可以复用本机学习目录。

本机实际使用的构建参数：

```bash
make check \
  BPFTOOL=/root/ebpf-learning/libbpf-bootstrap/examples/c/.output/bpftool/bootstrap/bpftool \
  LIBBPF_CFLAGS=-I/root/ebpf-learning/libbpf-bootstrap/examples/c/.output \
  LIBBPF_LIBS='/root/ebpf-learning/libbpf-bootstrap/examples/c/.output/libbpf.a -lelf -lz'

# 原阶段 1 示例用同样参数，通过 make -C src all 构建。
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py' -v
```

openEuler 24.03 LTS、内核 `6.6.0-28.0.0.34.oe2403.x86_64` 本机结果：

- 根目录全部九个 BPF 对象、execsnoop 与两个注入程序编译通过。
- `make check` 和 IO 桶边界/部分完成判定测试通过。
- 17 项真实内核/命令行集成测试全部通过：既有 exec_trace 6 项、IO 5 项、新 execsnoop 6 项。
- 新测试覆盖字段与顺序、时间戳、失败 exec 语义、collector stdin 消费、限时退出、
  pretty、特殊字符文件名、输出失败和非法参数。
- 既有 IO 直接读写测试保持通过：整盘 `8:0` 读 8 次 / 524288 字节，写 10 次 / 573440 字节。

其他五场景骨架只验证了编译，未宣称指标已实现或完成内核运行验收。
collector 仍为阶段 3 骨架，目前验证 JSONL 输入与事件计数，不宣称已输出七字段诊断报告。
系统版 libbpf-devel / bpftool 的默认链接方式、跨内核和跨架构运行仍待另行验证。

## 后续 Git 操作

本机添加 `gitlab` HTTPS 远程，`dev/yu` 默认向 GitLab 推送。
个人分支首次发布后设置跟踪 `gitlab/dev/yu`，后续以 GitLab 主干为同步依据：

```bash
git fetch gitlab
git switch dev/yu
git merge gitlab/main
git push gitlab dev/yu
# GitHub 镜像在可用时补同步个人分支。
git push origin dev/yu
```

main 仅由 owner 合并与推送，不使用 force，不改写既有评分历史。
当前 GitLab 凭据只使用临时内存缓存；到期后在虚拟机终端重新认证，凭据不进 Git 地址或版本库。

下一项开发仍是阶段 2 场景 1：sys_enter / sys_exit 配对、pid×syscall 的 map 聚合、
注入验证与摘要；其他场景继续按任务清单推进。
