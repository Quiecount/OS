# 阶段 0 环境验收记录（yu）

## 环境

- 系统：openEuler 24.03 LTS，x86_64
- 开发方式：VSCode Remote-SSH
- 项目开发分支：dev/yu

## libbpf-bootstrap minimal 验收

- 原验收源码目录：/root/ebpf-learning/libbpf-bootstrap
- 编译命令：在 examples/c 下执行 make minimal
- 编译结果：成功生成 minimal 可执行程序
- 运行方式：执行 ./minimal，另一终端读取 trace_pipe
- 实际输出示例：

  BPF triggered from PID 9932.

- 观察结果：约每秒输出一次，持续运行期间未观察到报错。
- 验收结论：minimal 编译、加载和事件输出通过。

## 遇到的问题

编译 bpftool 时缺少 openssl/opensslv.h。
执行 dnf install -y openssl-devel 后，重新编译成功。

## 学习成果迁入 OS（2026-11-18）

minimal 源码已整理到 `src/probes/minimal.bpf.c` 和 `src/loader/minimal.c`，
使用 `make -C src` 构建，原验收目录保留。
依赖与复现步骤见 [ebpf-learning 迁入说明](ebpf-learning迁入说明.md)。

迁入后复验：

- 环境：openEuler 24.03 LTS，内核 `6.6.0-28.0.0.34.oe2403.x86_64`。
- 编译：复用原学习目录的 libbpf 静态库和 bpftool，按迁入说明中的覆盖参数构建成功。
- 运行：Verifier 加载和 tracepoint 挂载成功，读取到与新加载器 PID 匹配的事件：

  ```text
  minimal-17400 [002] ....1 15602.389834: bpf_trace_printk: BPF triggered from PID 17400.
  ```

- 验证后已停止加载器；生成文件均位于被忽略的 `src/.output/`。
- 本机尚未安装系统版 libbpf-devel / bpftool，默认系统工具链构建方式未在本次复验。
