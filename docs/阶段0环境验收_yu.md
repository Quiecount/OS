# 阶段 0 环境验收记录（yu）

## 环境

- 系统：openEuler 24.03 LTS，x86_64
- 开发方式：VSCode Remote-SSH
- 项目开发分支：dev/yu

## libbpf-bootstrap minimal 验收

- 源码目录：/root/ebpf-learning/libbpf-bootstrap
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