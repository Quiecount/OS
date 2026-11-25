// 探针（场景2 骨架）：CPU 异常 / 调度延迟 —— 观测每次进程切换
// 挂载点：tracepoint/sched/sched_switch（每次 CPU 换进程都触发）
// 骨架现状：提交 prev/next 进程号；阶段 2 补 runqlat 直方图与 off-cpu 统计
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#include "events.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    struct ev_cpu *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->c.ts_ns = bpf_ktime_get_ns();
    e->c.pid = bpf_get_current_pid_tgid() >> 32;
    e->c.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->c.comm, sizeof(e->c.comm));
    e->prev_pid = ctx->prev_pid;     // 被换下的进程
    e->next_pid = ctx->next_pid;     // 换上的进程

    bpf_ringbuf_submit(e, 0);
    return 0;
}
