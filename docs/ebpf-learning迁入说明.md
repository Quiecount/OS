# ebpf-learning 学习成果迁入 OS

本次将 `/root/ebpf-learning/libbpf-bootstrap` 中已完成阶段 0 验收的
minimal 示例整理到 OS，继续在 `dev/yu` 分支学习和开发。
原学习目录保留，作为上游源码参考和已有工具链的来源。

## 文件对应

| 原 libbpf-bootstrap 路径 | OS 路径 | 用途 |
|---|---|---|
| `examples/c/minimal.bpf.c` | `src/probes/minimal.bpf.c` | 观测加载器自身的 write 系统调用 |
| `examples/c/minimal.c` | `src/loader/minimal.c` | 设置进程过滤、加载和挂载探针，每秒触发一次 write |
| `examples/c/Makefile` | `src/Makefile`（重新编写） | 编译探针、生成 skeleton、链接加载器 |

本示例属于第三方学习代码，来源与许可证见
[libbpf-bootstrap 版权说明](licenses/libbpf-bootstrap.md)。
探针保留上游实现；加载器调整注释、入口签名及 trace_pipe 提示路径。
构建改用可配置的 libbpf 和 bpftool，不依赖整个上游 Git 仓库。

## 编译和运行

在 openEuler 24.03 LTS、内核 6.6、x86_64 环境执行。从 OS 根目录开始：

```bash
# 首次准备系统工具链；已安装的包无需重复安装。
sudo dnf install -y clang llvm gcc make pkgconf-pkg-config libbpf-devel bpftool
make -C src

# 终端一：加载探针，Ctrl+C 退出。
sudo ./src/.output/minimal

# 终端二：读取内核输出，Ctrl+C 退出。
sudo cat /sys/kernel/tracing/trace_pipe
```

预期终端二每秒出现类似 `BPF triggered from PID 12345.` 的记录，PID 对应
minimal 加载器。它跟踪的是加载器自身的 `write`，用于验证编译、Verifier
加载和 tracepoint 挂载流程；数据通过 `bpf_printk` 输出。
ringbuf、JSON 和正式场景探针按开发计划后续阶段推进。

若尚未安装系统 libbpf-devel / bpftool，可复用原学习目录中已经构建好的工具：

```bash
make -C src \
  BPFTOOL=/root/ebpf-learning/libbpf-bootstrap/examples/c/.output/bpftool/bootstrap/bpftool \
  LIBBPF_CFLAGS=-I/root/ebpf-learning/libbpf-bootstrap/examples/c/.output \
  LIBBPF_LIBS='/root/ebpf-learning/libbpf-bootstrap/examples/c/.output/libbpf.a -lelf -lz'
```

该方式依赖本机原目录；其他成员可安装系统工具链后使用默认构建命令。
切换工具链时先执行 `make -C src clean` 再重新编译。

所有编译产物位于 `src/.output/`，已被 `.gitignore` 排除。
上游 `.git`、子模块、IDE 配置和原目录的二进制产物不纳入 OS。
