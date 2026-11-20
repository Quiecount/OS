#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "osmedic.h"

char LICENSE[] SEC("license") = "GPL";
const volatile unsigned int ignored_pid = 0;
static const struct cpu_stats empty_stats = {};

/* All switched-out time: runnable waiting as well as sleeping/blocked. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, unsigned int);
    __type(value, struct sched_queued);
} offcpu SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, unsigned int);
    __type(value, struct sched_queued);
} queued SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned int);
    __type(value, struct cpu_stats);
} cpu_totals SEC(".maps");

static __always_inline struct cpu_stats *get_stats(unsigned int pid,
                                                    struct task_struct *task)
{
    struct cpu_stats *stats = bpf_map_lookup_elem(&cpu_totals, &pid);
    if (!stats) {
        bpf_map_update_elem(&cpu_totals, &pid, &empty_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&cpu_totals, &pid);
        if (stats) {
            stats->uid = BPF_CORE_READ(task, real_cred, uid.val);
            bpf_core_read_str(stats->comm, sizeof(stats->comm), &task->comm);
        }
    }
    return stats;
}

static __always_inline int record_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    unsigned int tid, pid;
    struct sched_queued start = {.queued_ns = bpf_ktime_get_ns()};

    if (!task)
        return 0;
    tid = BPF_CORE_READ(task, pid);
    pid = BPF_CORE_READ(task, tgid);
    if (tid && pid && pid != ignored_pid)
        bpf_map_update_elem(&queued, &tid, &start, BPF_NOEXIST);
    return 0;
}

SEC("raw_tp/sched_wakeup")
int trace_sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
    return record_wakeup(ctx);
}

SEC("raw_tp/sched_wakeup_new")
int trace_sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx)
{
    return record_wakeup(ctx);
}

SEC("raw_tp/sched_switch")
int trace_sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    struct sched_queued *was_queued;
    struct sched_queued now_queued;
    struct cpu_stats *stats;
    unsigned long long now = bpf_ktime_get_ns();
    unsigned int prev_tid, next_tid, prev_pid, next_pid;

    if (!prev || !next)
        return 0;
    prev_tid = BPF_CORE_READ(prev, pid);
    next_tid = BPF_CORE_READ(next, pid);
    prev_pid = BPF_CORE_READ(prev, tgid);
    next_pid = BPF_CORE_READ(next, tgid);

    if (prev_tid && prev_pid && prev_pid != ignored_pid &&
        BPF_CORE_READ(prev, exit_state) == 0) {
        struct sched_queued stopped = {.queued_ns = now};
        bpf_map_update_elem(&offcpu, &prev_tid, &stopped, BPF_ANY);
    }
    struct sched_queued *stopped = bpf_map_lookup_elem(&offcpu, &next_tid);
    if (stopped) {
        if (next_pid && next_pid != ignored_pid && now >= stopped->queued_ns) {
            unsigned long long elapsed = now - stopped->queued_ns;
            stats = get_stats(next_pid, next);
            if (stats) {
                __sync_fetch_and_add(&stats->offcpu_total_ns, elapsed);
                __sync_fetch_and_add(&stats->offcpu_samples, 1);
            }
        }
        bpf_map_delete_elem(&offcpu, &next_tid);
    }

    /* Linux 6.6 supplies the state snapshot as arg 3. Preemption keeps
     * the task runnable even when its mutable task state is nonzero. */
    if (prev_tid && prev_pid && prev_pid != ignored_pid &&
        (ctx->args[0] || ctx->args[3] == 0)) {
        now_queued.queued_ns = now;
        bpf_map_update_elem(&queued, &prev_tid, &now_queued, BPF_ANY);
    }

    was_queued = bpf_map_lookup_elem(&queued, &next_tid);
    if (was_queued) {
        if (next_pid && next_pid != ignored_pid && now >= was_queued->queued_ns) {
            unsigned long long elapsed = now - was_queued->queued_ns;
            unsigned int slot = latency_bucket(elapsed);
            stats = get_stats(next_pid, next);
            if (stats) {
                __sync_fetch_and_add(&stats->runq_total_ns, elapsed);
                __sync_fetch_and_add(&stats->runq_samples, 1);
                __sync_fetch_and_add(&stats->runq_buckets[slot], 1);
            }
        }
        bpf_map_delete_elem(&queued, &next_tid);
    }
    return 0;
}

SEC("raw_tp/sched_process_exit")
int trace_sched_exit(struct bpf_raw_tracepoint_args *ctx)
{
    (void)ctx;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&queued, &tid);
    bpf_map_delete_elem(&offcpu, &tid);
    return 0;
}
