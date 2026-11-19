// 探针（场景5 骨架）：锁竞争 —— 观测 futex 系统调用（pthread 锁的底层实现）
// 挂载点：tracepoint/syscalls/sys_enter_futex
// 骨架现状：提交锁地址与操作码；阶段 2 补 enter/exit 配对计时 + 等待栈聚合
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#include "events.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_futex")
int trace_futex_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct ev_lock e = {};

    e.c.ts_ns = bpf_ktime_get_ns();
    e.c.pid = bpf_get_current_pid_tgid() >> 32;
    e.c.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e.c.comm, sizeof(e.c.comm));
    e.uaddr = (unsigned long)ctx->args[0];  // futex(uaddr, op, ...) 第一个参数：锁地址
    e.op = (int)ctx->args[1];               // 操作码（WAIT/WAKE 等）

    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}
