#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "osmedic.h"

char LICENSE[] SEC("license") = "GPL";
const volatile unsigned int ignored_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, unsigned int);
    __type(value, struct sched_running);
} running SEC(".maps");

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
        struct cpu_stats zero = {};
        zero.uid = BPF_CORE_READ(task, real_cred, uid.val);
        bpf_core_read_str(zero.comm, sizeof(zero.comm), &task->comm);
        bpf_map_update_elem(&cpu_totals, &pid, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&cpu_totals, &pid);
    }
    return stats;
}

static __always_inline unsigned int runq_slot(unsigned long long us)
{
    unsigned int slot = OSMEDIC_RUNQ_SLOTS - 1;
#pragma unroll
    for (int i = 0; i < OSMEDIC_RUNQ_SLOTS - 1; i++) {
        if (us <= (1ULL << i)) {
            slot = i;
            break;
        }
    }
    return slot;
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
    struct sched_running *was_running;
    struct sched_queued *was_queued;
    struct sched_running now_running;
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

    was_running = bpf_map_lookup_elem(&running, &prev_tid);
    if (was_running) {
        unsigned int running_pid = was_running->pid;
        unsigned long long started_ns = was_running->started_ns;
        if (running_pid && running_pid != ignored_pid && now >= started_ns) {
            stats = get_stats(running_pid, prev);
            if (stats)
                __sync_fetch_and_add(&stats->runtime_ns, now - started_ns);
        }
        bpf_map_delete_elem(&running, &prev_tid);
    }
    /* TASK_RUNNING (0) means the switched-out task is waiting for a CPU. */
    if (prev_tid && prev_pid && prev_pid != ignored_pid &&
        BPF_CORE_READ(prev, __state) == 0) {
        now_queued.queued_ns = now;
        bpf_map_update_elem(&queued, &prev_tid, &now_queued, BPF_ANY);
    }

    was_queued = bpf_map_lookup_elem(&queued, &next_tid);
    if (was_queued) {
        if (next_pid && next_pid != ignored_pid && now >= was_queued->queued_ns) {
            unsigned long long elapsed = now - was_queued->queued_ns;
            unsigned int slot = runq_slot(elapsed / 1000);
            stats = get_stats(next_pid, next);
            if (stats) {
                __sync_fetch_and_add(&stats->runq_total_ns, elapsed);
                __sync_fetch_and_add(&stats->runq_samples, 1);
                __sync_fetch_and_add(&stats->runq_buckets[slot], 1);
            }
        }
        bpf_map_delete_elem(&queued, &next_tid);
    }
    if (next_tid && next_pid && next_pid != ignored_pid) {
        now_running.started_ns = now;
        now_running.pid = next_pid;
        bpf_map_update_elem(&running, &next_tid, &now_running, BPF_ANY);
    }
    return 0;
}
