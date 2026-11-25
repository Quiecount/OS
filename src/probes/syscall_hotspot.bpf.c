// 探针（场景1 骨架）：syscall 热点 —— 观测所有系统调用的进入
// 挂载点：tracepoint/raw_syscalls/sys_enter（带 syscall 号，覆盖全部系统调用）
// 骨架现状：逐事件提交（演示通路）；阶段 2 改为 map 聚合（见 events.h 的 TODO）
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#include "events.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct ev_syscall *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->c.ts_ns = bpf_ktime_get_ns();
    e->c.pid = bpf_get_current_pid_tgid() >> 32;
    e->c.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->c.comm, sizeof(e->c.comm));
    e->id = ctx->id;                 // 系统调用号

    bpf_ringbuf_submit(e, 0);
    return 0;
}
