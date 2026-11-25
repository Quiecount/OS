#ifndef OSMEDIC_WINDOW_MERGE_H
#define OSMEDIC_WINDOW_MERGE_H

#include <stdlib.h>
#include "osmedic.h"

/* A producer may recreate a key while a HASH map is being drained. Merge all
 * fragments BEFORE CPU sampling, ranking, thresholds or streak accounting. */
struct cpu_row {
    unsigned int pid;
    struct cpu_stats stats;
    unsigned long long cpu_sample_start_ns, cpu_sample_end_ns;
    unsigned long long cpu_read_span_ns, process_start_ticks;
};
struct syscall_row { struct syscall_key key; struct syscall_stats value; };

static inline int cpu_pid_order(const void *a, const void *b)
{
    unsigned int x = ((const struct cpu_row *)a)->pid;
    unsigned int y = ((const struct cpu_row *)b)->pid;
    return (x > y) - (x < y);
}

static inline size_t merge_cpu_rows(struct cpu_row *rows, size_t n)
{
    qsort(rows, n, sizeof(*rows), cpu_pid_order);
    size_t out = 0;
    for (size_t i = 0; i < n; ++i) {
        if (!out || rows[out - 1].pid != rows[i].pid) {
            if (out != i) rows[out] = rows[i];
            ++out;
            continue;
        }
        struct cpu_stats *to = &rows[out - 1].stats, *from = &rows[i].stats;
        to->runtime_ns += from->runtime_ns;
        to->runq_total_ns += from->runq_total_ns;
        to->runq_samples += from->runq_samples;
        to->runq_over_threshold += from->runq_over_threshold;
        to->offcpu_total_ns += from->offcpu_total_ns;
        to->offcpu_samples += from->offcpu_samples;
        for (unsigned int j = 0; j < OSMEDIC_RUNQ_SLOTS; ++j)
            to->runq_buckets[j] += from->runq_buckets[j];
    }
    return out;
}

static inline int syscall_key_order(const void *a, const void *b)
{
    const struct syscall_key *x = &((const struct syscall_row *)a)->key;
    const struct syscall_key *y = &((const struct syscall_row *)b)->key;
    if (x->pid != y->pid) return (x->pid > y->pid) - (x->pid < y->pid);
    return (x->syscall_id > y->syscall_id) - (x->syscall_id < y->syscall_id);
}

static inline size_t merge_syscall_rows(struct syscall_row *rows, size_t n)
{
    qsort(rows, n, sizeof(*rows), syscall_key_order);
    size_t out = 0;
    for (size_t i = 0; i < n; ++i) {
        if (!out || syscall_key_order(&rows[out - 1], &rows[i])) {
            if (out != i) rows[out] = rows[i];
            ++out;
            continue;
        }
        struct syscall_stats *to = &rows[out - 1].value, *from = &rows[i].value;
        to->calls += from->calls;
        to->total_ns += from->total_ns;
        for (unsigned int j = 0; j < OSMEDIC_HIST_SLOTS; ++j)
            to->buckets[j] += from->buckets[j];
    }
    return out;
}
#endif
