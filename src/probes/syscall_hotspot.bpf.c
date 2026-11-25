#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "osmedic.h"

char LICENSE[] SEC("license") = "GPL";
const volatile unsigned int ignored_pid = 0;
const volatile unsigned int percpu_mode = 1;
/* Opt-in experiment: sched_switch invalidates this CPU's active timestamp. */
const volatile unsigned int cached_exit_identity = 0;
static const struct syscall_stats empty_stats = {};

struct syscall_fast {
    unsigned long long tid;
    struct syscall_start start;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct syscall_fast);
} fast_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, unsigned long long);
    __type(value, struct syscall_start);
} syscall_starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct syscall_key);
    __type(value, struct syscall_stats);
} syscall_totals SEC(".maps");

SEC("raw_tp/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long long tid = bpf_get_current_pid_tgid();
    unsigned int zero = 0;

    /* Avoid observing the monitor's own map syscalls. */
    if ((tid >> 32) == 0 || (tid >> 32) == ignored_pid)
        return 0;
    /* BPF execution cannot migrate. sched_switch spills an active entry to
     * the TID map before another task can reuse this CPU's cache. */
    struct syscall_fast *cached = bpf_map_lookup_elem(&fast_start, &zero);
    if (cached) {
        cached->tid = tid;
        cached->start.syscall_id = (unsigned int)ctx->args[1];
        cached->start.started_ns = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("raw_tp/sys_exit")
int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long long tid;
    struct syscall_start *start;
    struct syscall_key key = {};
    struct syscall_stats *stats;
    unsigned long long elapsed;
    unsigned int slot;
    unsigned int zero = 0;

    (void)ctx;
    struct syscall_fast *cached = bpf_map_lookup_elem(&fast_start, &zero);
    /* An active cache necessarily belongs to the current task: switching out
     * spills and invalidates it, and sys_enter records the new identity.
     * Only the suspended/migrated path needs to read the task identity again. */
    if (cached_exit_identity && cached && cached->start.started_ns)
        tid = cached->tid;
    else
        tid = bpf_get_current_pid_tgid();
    if ((tid >> 32) == 0 || (tid >> 32) == ignored_pid)
        return 0;
    int fast = cached && cached->tid == tid && cached->start.started_ns;
    start = fast ? &cached->start : bpf_map_lookup_elem(&syscall_starts, &tid);
    if (!start || !start->started_ns)
        return 0;
    elapsed = bpf_ktime_get_ns() - start->started_ns;
    key.pid = tid >> 32;
    key.syscall_id = start->syscall_id;
    /* An unmatched exit must never reuse a previous syscall's timestamp. */
    start->started_ns = 0;
    if (!fast) bpf_map_delete_elem(&syscall_starts, &tid);
    if (!key.pid)
        return 0;
    stats = bpf_map_lookup_elem(&syscall_totals, &key);
    if (!stats) {
        /* Read-only template avoids placing a histogram on the BPF stack. */
        bpf_map_update_elem(&syscall_totals, &key, &empty_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_totals, &key);
    }
    if (!stats)
        return 0;
    if (!stats->calls) {
        stats->uid = (unsigned int)bpf_get_current_uid_gid();
        bpf_get_current_comm(stats->comm, sizeof(stats->comm));
    }
    slot = latency_bucket(elapsed);
    /* sys_exit is non-migrating and cannot recursively issue another syscall.
     * Per-CPU counters avoid sharing atomic cache lines between worker CPUs. */
    if (percpu_mode) {
        stats->calls++;
        stats->total_ns += elapsed;
        stats->buckets[slot]++;
    } else {
        __sync_fetch_and_add(&stats->calls, 1);
        __sync_fetch_and_add(&stats->total_ns, elapsed);
        __sync_fetch_and_add(&stats->buckets[slot], 1);
    }
    return 0;
}

SEC("raw_tp/sched_switch")
int trace_syscall_switch(struct bpf_raw_tracepoint_args *ctx)
{
    (void)ctx;
    unsigned int zero = 0;
    struct syscall_fast *cached = bpf_map_lookup_elem(&fast_start, &zero);
    if (cached && cached->start.started_ns) {
        bpf_map_update_elem(&syscall_starts, &cached->tid, &cached->start, BPF_ANY);
        cached->start.started_ns = 0;
    }
    return 0;
}

SEC("raw_tp/sched_process_exit")
int trace_syscall_task_exit(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long long tid = bpf_get_current_pid_tgid();
    unsigned int zero = 0;
    struct syscall_fast *cached = bpf_map_lookup_elem(&fast_start, &zero);
    if (cached && cached->tid == tid) cached->start.started_ns = 0;
    (void)ctx;
    bpf_map_delete_elem(&syscall_starts, &tid);
    return 0;
}
