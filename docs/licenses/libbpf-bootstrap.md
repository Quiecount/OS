# libbpf-bootstrap minimal 来源与许可证

来源：本机 `/root/ebpf-learning/libbpf-bootstrap`，上游仓库
<https://github.com/libbpf/libbpf-bootstrap>。
导入版本：`ac021d82163db8e29374e31befd6cac013f562f9`。

| OS 文件 | 上游文件 | 上游 SPDX 标识 |
|---|---|---|
| `src/probes/minimal.bpf.c` | `examples/c/minimal.bpf.c` | `GPL-2.0 OR BSD-3-Clause` |
| `src/loader/minimal.c` | `examples/c/minimal.c` | `LGPL-2.1 OR BSD-2-Clause` |
| `src/probes/exec_trace.bpf.c` | 参考并改造 `examples/c/bootstrap.bpf.c` 的 exec/ringbuf 部分 | `GPL-2.0 OR BSD-3-Clause` |

上述源码文件保留各自的 SPDX 与 Facebook 版权声明。本次分别采用 BSD
许可选项；这些声明仅适用于导入的示例，不为 OS 仓库其他文件指定许可证。
探针保持原实现；加载器调整中文注释、入口签名、未使用参数处理和输出路径提示。
`src/Makefile` 为本次整理重新编写。

阶段 1 的 exec 探针保留成功 exec 挂载点及 ringbuf 采集方式，新增 PID 过滤、
UID、单调时钟时间戳、丢失计数和字符串读取状态，省去原示例的进程退出追踪。
`src/loader/exec_trace.c` 与 `src/probes/exec_trace.h` 为本仓库新增实现。

## 上游仓库 LICENSE 原文（BSD-3-Clause）

```text
BSD 3-Clause License

Copyright (c) 2020, Andrii Nakryiko
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

探针文件同时保留 `Copyright (c) 2020 Facebook`，适用上述 BSD-3-Clause 条款。

## 加载器采用的 BSD-2-Clause 条款

```text
Copyright (c) 2020 Facebook

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
