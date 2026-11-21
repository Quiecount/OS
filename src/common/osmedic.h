#ifndef OSMEDIC_COMMON_H
#define OSMEDIC_COMMON_H

#define OSMEDIC_COMM_LEN 16
#define OSMEDIC_PATH_LEN 256
#define OSMEDIC_DISK_LEN 32
#include "latency_hist.h"
#define OSMEDIC_HIST_SLOTS OSMEDIC_FINE_SLOTS
#define OSMEDIC_RUNQ_SLOTS OSMEDIC_FINE_SLOTS

struct exec_event {
    unsigned long long ktime_ns;
    unsigned int pid;
    unsigned int tid;
    unsigned int uid;
    int filename_len;
    char comm[OSMEDIC_COMM_LEN];
    char filename[OSMEDIC_PATH_LEN];
};

struct io_start {
    unsigned long long started_ns;
    unsigned long long bytes;
    unsigned int pid;
    unsigned int major;
    unsigned int minor;
    unsigned int op;
    char comm[OSMEDIC_COMM_LEN];
    char disk[OSMEDIC_DISK_LEN];
};

struct io_hist_key {
    unsigned int major;
    unsigned int minor;
    unsigned int slot;
    char disk[OSMEDIC_DISK_LEN];
};

struct syscall_key {
    unsigned int pid;
    unsigned int syscall_id;
};

struct syscall_start {
    unsigned long long started_ns;
    unsigned int syscall_id;
};

struct syscall_stats {
    unsigned long long calls;
    unsigned long long total_ns;
    unsigned long long buckets[OSMEDIC_HIST_SLOTS];
    unsigned int uid;
    char comm[OSMEDIC_COMM_LEN];
};

struct sched_running {
    unsigned long long started_ns;
    unsigned int pid;
};

struct sched_queued {
    unsigned long long queued_ns;
};

struct cpu_stats {
    unsigned long long runtime_ns;
    unsigned long long runq_total_ns;
    unsigned long long runq_samples;
    unsigned long long runq_over_threshold;
    unsigned long long offcpu_total_ns;
    unsigned long long offcpu_samples;
    unsigned long long runq_buckets[OSMEDIC_RUNQ_SLOTS];
    unsigned int uid;
    char comm[OSMEDIC_COMM_LEN];
};

#endif
