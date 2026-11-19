#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "osmedic.h"

char LICENSE[] SEC("license") = "GPL";
const volatile unsigned int ignored_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, unsigned long long);
    __type(value, struct syscall_start);
} syscall_starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct syscall_key);
    __type(value, struct syscall_stats);
} syscall_totals SEC(".maps");

static __always_inline unsigned int latency_slot(unsigned long long us)
{
    unsigned int slot = OSMEDIC_HIST_SLOTS - 1;
#pragma unroll
    for (int i = 0; i < OSMEDIC_HIST_SLOTS - 1; i++) {
        if (us <= (1ULL << i)) {
            slot = i;
            break;
        }
    }
    return slot;
}

SEC("raw_tp/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long long tid = bpf_get_current_pid_tgid();
    struct syscall_start start = {
        .started_ns = bpf_ktime_get_ns(),
        .syscall_id = (unsigned int)ctx->args[1],
    };

    /* Avoid observing the monitor's own map syscalls. */
    if ((tid >> 32) == 0 || (tid >> 32) == ignored_pid)
        return 0;
    bpf_map_update_elem(&syscall_starts, &tid, &start, BPF_ANY);
    return 0;
}

SEC("raw_tp/sys_exit")
int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long long tid = bpf_get_current_pid_tgid();
    struct syscall_start *start;
    struct syscall_key key = {};
    struct syscall_stats zero = {};
    struct syscall_stats *stats;
    unsigned long long elapsed;
    unsigned int slot;

    (void)ctx;
    start = bpf_map_lookup_elem(&syscall_starts, &tid);
    if (!start)
        return 0;
    elapsed = bpf_ktime_get_ns() - start->started_ns;
    key.pid = tid >> 32;
    key.syscall_id = start->syscall_id;
    bpf_map_delete_elem(&syscall_starts, &tid);
    if (!key.pid)
        return 0;
    stats = bpf_map_lookup_elem(&syscall_totals, &key);
    if (!stats) {
        bpf_get_current_comm(zero.comm, sizeof(zero.comm));
        bpf_map_update_elem(&syscall_totals, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_totals, &key);
    }
    if (!stats)
        return 0;
    slot = latency_slot(elapsed / 1000);
    __sync_fetch_and_add(&stats->calls, 1);
    __sync_fetch_and_add(&stats->total_ns, elapsed);
    __sync_fetch_and_add(&stats->buckets[slot], 1);
    return 0;
}
