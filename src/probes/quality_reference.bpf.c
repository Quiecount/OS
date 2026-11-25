/* Test-only reference: raw per-event durations, never used for performance runs. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
char LICENSE[] SEC("license") = "GPL";
const volatile unsigned int target_pid;
const volatile unsigned int syscall_id;
struct quality_sample { unsigned long long ns; unsigned int kind, tid; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
    __type(key, unsigned int); __type(value, unsigned long long);
} entered SEC(".maps"), ready SEC(".maps"), stopped SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 22); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, unsigned int); __type(value, unsigned long long); } lost SEC(".maps");
static __always_inline void emit(unsigned int kind, unsigned int tid, unsigned long long elapsed)
{
    struct quality_sample *s = bpf_ringbuf_reserve(&events, sizeof(*s), 0);
    if (!s) { unsigned int k = 0; unsigned long long *v = bpf_map_lookup_elem(&lost, &k);
        if (v) __sync_fetch_and_add(v, 1); return; }
    s->ns = elapsed; s->kind = kind; s->tid = tid; bpf_ringbuf_submit(s, 0);
}
SEC("raw_tp/sys_enter") int enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long long id = bpf_get_current_pid_tgid(), now = bpf_ktime_get_ns();
    unsigned int tid = id;
    if (id >> 32 == target_pid && ctx->args[1] == syscall_id)
        bpf_map_update_elem(&entered, &tid, &now, BPF_ANY);
    return 0;
}
SEC("raw_tp/sys_exit") int leave(struct bpf_raw_tracepoint_args *ctx)
{
    (void)ctx; unsigned long long id = bpf_get_current_pid_tgid(); unsigned int tid = id;
    if (id >> 32 != target_pid) return 0;
    unsigned long long *start = bpf_map_lookup_elem(&entered, &tid);
    if (start) { emit(0, tid, bpf_ktime_get_ns() - *start); bpf_map_delete_elem(&entered, &tid); }
    return 0;
}
static __always_inline int wake(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (void *)ctx->args[0];
    unsigned int pid = BPF_CORE_READ(task, tgid), tid = BPF_CORE_READ(task, pid);
    unsigned long long now = bpf_ktime_get_ns();
    if (pid == target_pid) bpf_map_update_elem(&ready, &tid, &now, BPF_NOEXIST);
    return 0;
}
SEC("raw_tp/sched_wakeup") int wakeup(struct bpf_raw_tracepoint_args *ctx) { return wake(ctx); }
SEC("raw_tp/sched_wakeup_new") int wakeup_new(struct bpf_raw_tracepoint_args *ctx) { return wake(ctx); }
SEC("raw_tp/sched_switch") int change(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *prev = (void *)ctx->args[1], *next = (void *)ctx->args[2];
    unsigned int a = BPF_CORE_READ(prev, pid), b = BPF_CORE_READ(next, pid);
    unsigned long long now = bpf_ktime_get_ns();
    if (BPF_CORE_READ(prev, tgid) == target_pid) {
        bpf_map_update_elem(&stopped, &a, &now, BPF_ANY);
        if (ctx->args[0] || ctx->args[3] == 0) bpf_map_update_elem(&ready, &a, &now, BPF_ANY);
    }
    if (BPF_CORE_READ(next, tgid) == target_pid) {
        unsigned long long *start = bpf_map_lookup_elem(&stopped, &b);
        if (start) { emit(2, b, now - *start); bpf_map_delete_elem(&stopped, &b); }
        start = bpf_map_lookup_elem(&ready, &b);
        if (start) { emit(1, b, now - *start); bpf_map_delete_elem(&ready, &b); }
    }
    return 0;
}
