# 开发指南 · 第一支探针 execsnoop

> 对应《开发计划》阶段 0→1 的衔接任务：写出**自己的第一支 eBPF 探针**。
> **所有操作都在 openEuler 24.03 虚拟机里做**（VSCode Remote-SSH 连进 VM，在仓库根目录操作）。
> 读不懂代码没关系，先把 §五 的命令跑通，再回头读 §六 的走读。

---

## 一、目标：做出什么

一个**进程启动追踪器**：系统里任何进程每次被启动，屏幕立刻打印一行——

```
PID      UID      COMM            FILENAME
2981     0        bash            /usr/bin/ls
2982     1000     sshd            /usr/bin/bash
```

它是后续全部五场景探针的**模板**。学会这一支的"探针 + 加载器 + Makefile"三件套，之后每个场景探针都只是：换个挂载点、换几个采集字段。

**验收标准（阶段 0 出口）**：
1. `make` 一次编译通过
2. `sudo ./build/execsnoop` 运行后，另开终端敲命令能看到事件输出
3. 能向队友讲清楚"一次 execve 从内核到屏幕"的完整路径

## 二、原理：数据是怎么流到屏幕上的

```
┌─────────────────── 内核态 ────────────────────┐
│ 任何进程调用 execve()                          │
│        │ 触发                                 │
│        ▼                                      │
│ trace_execve 探针函数自动运行（几十行 C）       │
│   ├─ helper 取 pid / uid / 进程名              │
│   ├─ helper 安全拷贝 filename（用户态指针）     │
│   └─ bpf_ringbuf_submit() 把事件丢进环形队列    │
└──────────────────────┬────────────────────────┘
                       │ ringbuf（events map）
┌──────────────────────▼────────────────────────┐
│ 加载器 ./execsnoop（用户态，普通 C 程序）        │
│   ring_buffer__poll() 收到事件 → 回调打印       │
└───────────────────────────────────────────────┘
```

五个必须认识的概念（代码里都会见到）：

| 概念 | 代码里的样子 | 一句话解释 |
|---|---|---|
| 挂载点 | `SEC("tracepoint/syscalls/sys_enter_execve")` | 探针的"插座"：内核在 execve 入口埋好的官方事件点 |
| map | `struct {...} events SEC(".maps")` | 内核态↔用户态的数据通道，我们用 ringbuf 类型 |
| helper | `bpf_get_current_comm(...)` 等 | 内核预注册的安全函数，探针只能调用这些 |
| Verifier | 加载时自动运行 | 内核安检员：模拟执行探针的每条路径，不安全就拒绝加载 |
| vmlinux.h | `#include "vmlinux.h"` | 当前内核全部类型定义的"翻译件"，make 自动从 BTF 生成 |

## 三、文件结构（探针三件套）

| 文件 | 角色 | 说明 |
|---|---|---|
| `src/probes/execsnoop.bpf.c` | **探针**（内核态） | clang 编译成 BPF 字节码，装进内核运行 |
| `src/loader/execsnoop.c` | **加载器**（用户态） | gcc 编译成普通程序：装探针、收事件、打印 |
| `src/event.h` | 共享结构体 | 两边都 include，保证事件布局一字节不差 |
| `Makefile` | 构建 | 一条 make 全搞定 |
| `src/vmlinux.h` | 自动生成 | make 时从 `/sys/kernel/btf/vmlinux` 生成，**不入库** |
| `build/` | 产物目录 | **不入库** |

## 四、环境准备（VM 内，一次性）

```bash
sudo dnf install -y gcc clang llvm make bpftool libbpf-devel

# 验证三件事：
clang --version                      # 编译器
bpftool version                      # 生成 vmlinux.h 的工具
ls /sys/kernel/btf/vmlinux           # 内核带 BTF（openEuler 24.03 一定有）
```

> 为什么不需要装 kernel-devel？因为我们用 vmlinux.h 替代了对内核头文件的依赖——这正是 CO-RE"一次编译、到处运行"的意义。

## 五、构建与运行（以后的日常循环）

### 第 0 步：第一次先把仓库克隆进 VM（只需一次）

虚拟机和 Windows 是两套独立系统，代码不会自动出现在 VM 里——先从比赛仓库克隆一份：

```bash
cd ~
git clone https://gitlab.eduxiji.net/T2026103369913109/project3331747-425741.git OS
# 登录：用户名 T2026103369913109，密码 = educg 平台密码
cd OS
```

（以后更新代码只需在此目录 `git pull`。）

### 编译与运行

```bash
cd ~/OS            # 仓库根目录（按你 VM 里的实际路径）
make               # 编译；第一次会自动生成 vmlinux.h，稍慢属正常
sudo ./build/execsnoop
```

保持它运行，**另开一个终端**随便执行命令（`ls`、`bash`、`vim`…），回到第一个终端——每次进程启动都会打印一行。`Ctrl+C` 退出。

预期输出：

```
PID      UID      COMM            FILENAME
按 Ctrl+C 退出
3041     0        bash            /usr/bin/ls
3055     1000     sshd            /usr/bin/bash
```

## 六、代码走读（配合源文件里的注释）

### 6.1 探针侧（src/probes/execsnoop.bpf.c）的 5 个关键点

1. **`SEC("tracepoint/...")`**——把函数声明成探针并指定插座；函数名 `trace_execve` 是加载器查找程序的依据
2. **`struct event e = {};`**——必须清零再填字段，读未初始化内存会被 Verifier 直接拒绝
3. **三个 helper**：`bpf_get_current_pid_tgid()`（高 32 位是 PID）、`bpf_get_current_comm()`、`bpf_probe_read_user_str()`——execve 传进来的 filename 是**用户态指针**，绝不能直接解引用，必须用 helper 拷贝
4. **`bpf_ringbuf_submit()`**——事件入队；之后打印、过滤、分析全是用户态的事（复杂逻辑放用户态，探针只做采集）
5. **`char LICENSE[] SEC("license")`**——tracepoint 程序要求 GPL 兼容声明

### 6.2 加载器侧（src/loader/execsnoop.c）的四步生命周期

```
open（读 .o 文件）→ load（Verifier 安检 + JIT）→ attach（挂上插座）→ poll（循环收事件）
```

libbpf API 一一对应：`bpf_object__open_file` / `bpf_object__load` / `bpf_program__attach` / `ring_buffer__poll`。**这个骨架以后所有探针都复用**。

### 6.3 Makefile 的三段编译

1. `bpftool btf dump ... > src/vmlinux.h`：从运行中内核的 BTF 生成类型头（只在缺失时执行）
2. `clang -target bpf`：把探针编译成 **BPF 字节码**——注意不是本机 x86 机器码
3. `gcc`：把加载器编译成本机程序，链接 `-lbpf -lelf -lz`

## 七、常见报错排查

| 报错 | 原因与解法 |
|---|---|
| `Operation not permitted` | 没有 sudo。加载 eBPF 程序需要 root |
| 打不开 `build/execsnoop.bpf.o` | 先 `make`；且必须在**仓库根目录**运行（加载器按相对路径找 .o 文件） |
| `bpftool: command not found` | `dnf install bpftool` |
| vmlinux.h 生成失败 | 确认 `ls /sys/kernel/btf/vmlinux` 存在；`make clean` 后重试 |
| `libbpf.so` 找不到 | 没装 `libbpf-devel` |
| load 失败 + 一大段 verifier 日志 | 读日志**最后几行**：几乎都是"读了未初始化内存"或"越界访问"，对照 §6.1 第 2、3 点检查 |
| 能运行但没输出 | 另开的终端真的产生了新进程吗？`ls` 会以 bash 子进程形式触发 execve；确认程序跑在 VM 里而不是 Windows |

## 八、练习（跑通后选做，阶段 1 热身）

1. 给输出加时间戳（提示：只改用户态 printf 加 `time()`，不用动探针）
2. 只打印某个用户的事件（提示：探针里加 `if (e.uid != 1000) return 0;`——**过滤要趁早**，在内核态做比用户态做省得多）
3. 把挂载点换成 `sys_enter_openat`，做一个小 opensnoop（观察文件打开）
4. 思考题：为什么敲一次 `ls`，输出里 `COMM` 显示 `bash`？（提示：shell 先 fork 自己，再 execve 成 ls）

## 九、完成之后

```bash
git add . && git commit -m "feat: 探针① execsnoop（进程启动追踪）" && git push gitlab main
```

然后对照《开发计划》§五 阶段 1 清单，开工探针②（块设备 IO 延迟直方图）。
