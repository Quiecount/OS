// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "stage2.h"
char LICENSE[] SEC("license") = "GPL";
const volatile __u32 target_pid, ignored_pid;
__u64 tracking_failures, ringbuf_dropped, active_waits;
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384);
    __type(key, __u32); __type(value, struct p2_wait);
} waits SEC(".maps");
/* 不删除零计数，避免 inc/dec 与删除竞态；容量耗尽显式记录失败。 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, P2_ROWS);
    __type(key, struct p2_lock_key); __type(value, __u64);
} counts SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE); __uint(max_entries, P2_ROWS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, P2_STACK_DEPTH * sizeof(__u64));
} stacks SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024); } events SEC(".maps");

static __always_inline void release_wait(struct p2_wait *w)
{
    struct p2_lock_key key = {w->e.process_start_ns, w->e.uaddr, w->e.c.pid, 0};
    __u64 *count = bpf_map_lookup_elem(&counts, &key);
    if (count) __sync_fetch_and_sub(count, 1);
    __sync_fetch_and_sub(&active_waits, 1);
}

SEC("tp/syscalls/sys_enter_futex")
int enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 zero = 0;
    struct p2_wait w = {};
    struct p2_lock_key key = {};
    __u64 *count;
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tid = id;
    w.e.c.pid = id >> 32;
    if (w.e.c.pid == ignored_pid || (target_pid && w.e.c.pid != target_pid)) return 0;
    w.e.op = ctx->args[1] & 0x7f; /* FUTEX_CMD_MASK: private/clock flags 不构成操作 */
    if (w.e.op != 0 && w.e.op != 9) return 0; /* WAIT / WAIT_BITSET */
    w.e.process_start_ns = key.start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    w.e.uaddr = key.addr = ctx->args[0]; key.pid = w.e.c.pid;
    w.e.c.uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(w.e.c.comm, sizeof(w.e.c.comm));
    w.e.tid = tid;
    w.e.stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
    bpf_map_update_elem(&counts, &key, &zero, BPF_NOEXIST);
    count = bpf_map_lookup_elem(&counts, &key);
    if (!count) { __sync_fetch_and_add(&tracking_failures, 1); return 0; }
    w.e.waiter_count = __sync_fetch_and_add(count, 1) + 1;
    w.started_ns = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&waits, &tid, &w, BPF_NOEXIST)) {
        __sync_fetch_and_sub(count, 1);
        __sync_fetch_and_add(&tracking_failures, 1);
    } else __sync_fetch_and_add(&active_waits, 1);
    return 0;
}

SEC("raw_tp/sched_switch")
int sleeping_stack(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *prev = (void *)ctx->args[1], *next = (void *)ctx->args[2];
    __u32 tid = BPF_CORE_READ(prev, pid);
    struct p2_wait *w = bpf_map_lookup_elem(&waits, &tid);
    __u64 now = bpf_ktime_get_ns();
    if (w) {
        w->offcpu_start_ns = now;
        w->e.stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
    }
    tid = BPF_CORE_READ(next, pid);
    w = bpf_map_lookup_elem(&waits, &tid);
    if (w && w->offcpu_start_ns) {
        w->e.offcpu_ns += now - w->offcpu_start_ns;
        w->offcpu_start_ns = 0;
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_futex")
int leave(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = bpf_get_current_pid_tgid();
    struct p2_wait *w = bpf_map_lookup_elem(&waits, &tid);
    if (!w) return 0;
    w->e.c.ts_ns = bpf_ktime_get_ns();
    w->e.wait_ns = w->e.c.ts_ns - w->started_ns; w->e.ret = ctx->ret;
    struct ev_lock *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        __sync_fetch_and_add(&ringbuf_dropped, 1);
    else {
        __builtin_memcpy(event, &w->e, sizeof(*event));
        bpf_ringbuf_submit(event, 0);
    }
    release_wait(w); bpf_map_delete_elem(&waits, &tid);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int cleanup(void *ctx)
{
    __u32 tid = bpf_get_current_pid_tgid();
    struct p2_wait *w = bpf_map_lookup_elem(&waits, &tid);
    if (w) { release_wait(w); bpf_map_delete_elem(&waits, &tid); }
    return 0;
}
