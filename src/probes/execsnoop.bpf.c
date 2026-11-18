// 探针①：execsnoop —— 追踪系统里每一次进程启动（execve 系统调用）
// 挂载点：tracepoint/syscalls/sys_enter_execve
// 数据通路：探针函数 → ringbuf(events) → 用户态加载器打印
// 这是后续五场景探针的模板，请配合 docs/开发指南_第一支探针execsnoop.md 阅读
//
// 注意：本文件由 clang -target bpf 编译成 BPF 字节码，运行在内核里；
// 写法受 Verifier 约束（无任意循环、栈 ≤512B、只能调 helper 函数）

#include "vmlinux.h"         // 当前内核的全部类型定义（Makefile 从 BTF 自动生成）
#include <bpf/bpf_helpers.h> // SEC / map 宏 / helper 函数声明

// 许可证声明：tracepoint 类程序要求 GPL 兼容许可证
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#include "event.h"

// 事件队列：BPF 环形缓冲区（内核态写、用户态读）
// 256KB 足够吸收事件洪峰；ringbuf 需要 5.8+ 内核，openEuler 24.03（6.6）满足
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 挂载到 execve 系统调用入口：任何进程每次执行 execve 都触发本函数
// ctx 是内核传给 tracepoint 的现场（args[] 里是系统调用参数）
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event e = {};   // 必须清零！读未初始化内存会被 Verifier 直接拒绝

    // 三个内核预注册的 helper：取当前进程的 pid / uid / 进程名
    e.pid = bpf_get_current_pid_tgid() >> 32;      // 返回值高 32 位是 pid
    e.uid = bpf_get_current_uid_gid();             // 返回值低 32 位是 uid
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // execve 的第一个参数（args[0]）是文件名指针，位于用户态地址空间
    // 用户态指针绝不能直接解引用（会被 Verifier 拒绝），必须用 helper 安全拷贝
    bpf_probe_read_user_str(e.filename, sizeof(e.filename),
                            (const void *)ctx->args[0]);

    // 事件入队，交给用户态；后续打印、过滤、分析都在用户态做
    bpf_ringbuf_submit(&e, sizeof(e), 0);
    return 0;
}
