// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "stage2.h"
char LICENSE[] SEC("license") = "GPL";
const volatile __u32 target_pid, ignored_pid;
__u64 tracking_failures, ringbuf_dropped;
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, P2_ROWS);
    __type(key, struct p2_process); __type(value, struct p2_mem_stats);
} totals SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384);
    __type(key, __u32); __type(value, struct p2_mmap);
} mmaps SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024); } events SEC(".maps");

static __always_inline struct p2_mem_stats *stats(struct p2_process *key)
{
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    struct p2_mem_stats zero = {}, *s;
    key->pid = bpf_get_current_pid_tgid() >> 32;
    if (key->pid == ignored_pid || (target_pid && key->pid != target_pid)) return 0;
    key->start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    s = bpf_map_lookup_elem(&totals, key);
    if (!s) {
        bpf_map_update_elem(&totals, key, &zero, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&totals, key);
    }
    if (!s) { __sync_fetch_and_add(&tracking_failures, 1); return 0; }
    s->c.ts_ns = bpf_ktime_get_ns();
    s->c.pid = key->pid;
    s->c.uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(s->c.comm, sizeof(s->c.comm));
    return s;
}

SEC("tp/exceptions/page_fault_user")
int fault(struct trace_event_raw_x86_exceptions *ctx)
{
    struct p2_process key = {};
    struct p2_mem_stats *s = stats(&key);
    if (s) { s->faults++; s->addr = ctx->address; }
    return 0;
}

SEC("tp/syscalls/sys_enter_mmap")
int mmap_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct p2_process key = {};
    struct p2_mem_stats *s;
    struct p2_mmap m = {};
    __u32 tid = bpf_get_current_pid_tgid();
    if (ctx->args[1] < (1 << 20)) return 0;
    s = stats(&key);
    if (!s) return 0;
    s->mmap_calls++;
    s->mmap_bytes += ctx->args[1];
    m.process = key; m.length = ctx->args[1];
    if (bpf_map_update_elem(&mmaps, &tid, &m, BPF_ANY))
        __sync_fetch_and_add(&tracking_failures, 1);
    return 0;
}

SEC("tp/syscalls/sys_exit_mmap")
int mmap_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = bpf_get_current_pid_tgid();
    struct p2_mmap *m = bpf_map_lookup_elem(&mmaps, &tid);
    if (!m) return 0;
    if (ctx->ret < 0 && ctx->ret >= -4095) {
        struct p2_mem_stats *s = bpf_map_lookup_elem(&totals, &m->process);
        if (s) s->mmap_failures++;
    }
    bpf_map_delete_elem(&mmaps, &tid);
    return 0;
}

SEC("tp_btf/mark_victim")
int BPF_PROG(oom, int pid)
{
    if (target_pid && (__u32)pid != target_pid) return 0;
    struct ev_mem *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&ringbuf_dropped, 1);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->c.ts_ns = bpf_ktime_get_ns(); e->c.pid = pid; e->kind = 1;
    /* tracepoint 只给 victim PID；禁止从 current 伪造 victim 的 uid/comm。 */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int cleanup(void *ctx)
{
    __u32 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&mmaps, &tid);
    return 0;
}
