#ifndef OSMEDIC_PROC_CPU_H
#define OSMEDIC_PROC_CPU_H

#include <dirent.h>
#include <sys/stat.h>

/* CPU accounting is cumulative in /proc, including time without a switch.
 * PID plus start time distinguishes a new process from a reused PID. */
struct proc_cpu_sample {
    unsigned int pid;
    unsigned long long start_ticks, cpu_ticks;
    unsigned long long sampled_ns;
    bool seen;
};
static struct proc_cpu_sample proc_samples[MAX_ROWS];

static int sample_process_cpu(struct cpu_row *rows, size_t *n)
{
    DIR *dir = opendir("/proc");
    struct dirent *entry;
    long hz = sysconf(_SC_CLK_TCK);
    if (!dir || hz <= 0) {
        if (dir) closedir(dir);
        return -1;
    }
    for (size_t i = 0; i < MAX_ROWS; ++i) proc_samples[i].seen = false;
    for (size_t i = 0; i < *n; ++i) rows[i].stats.runtime_ns = 0;
    while ((entry = readdir(dir))) {
        char *tail;
        unsigned long pid = strtoul(entry->d_name, &tail, 10);
        if (*tail || !pid || pid > UINT32_MAX || pid == (unsigned int)getpid()) continue;
        char path[64], buf[4096], comm[OSMEDIC_COMM_LEN] = {};
        snprintf(path, sizeof(path), "/proc/%lu/stat", pid);
        FILE *file = fopen(path, "r");
        if (!file) continue; /* A process may exit during enumeration. */
        struct stat info;
        unsigned long long read_begin = monitor_now_ns(CLOCK_MONOTONIC);
        bool ok = !fstat(fileno(file), &info) && fgets(buf, sizeof(buf), file);
        unsigned long long read_end = monitor_now_ns(CLOCK_MONOTONIC);
        unsigned long long sampled_ns = read_begin + (read_end - read_begin) / 2;
        fclose(file);
        if (!ok) continue;
        char *first = strchr(buf, '('), *last = strrchr(buf, ')');
        if (!first || !last || last <= first || last[1] != ' ') continue;
        size_t len = (size_t)(last - first - 1);
        if (len >= sizeof(comm)) len = sizeof(comm) - 1;
        memcpy(comm, first + 1, len);
        unsigned long long ticks = 0, start = 0;
        char *save = NULL, *token = strtok_r(last + 2, " ", &save);
        unsigned int field;
        for (field = 3; field <= 22 && token; ++field) {
            if (field == 14 || field == 15) ticks += strtoull(token, NULL, 10);
            if (field == 22) start = strtoull(token, NULL, 10);
            token = strtok_r(NULL, " ", &save);
        }
        if (field <= 22 || !start) continue;
        struct proc_cpu_sample *previous = NULL, *empty = NULL;
        for (size_t i = 0; i < MAX_ROWS; ++i) {
            if (proc_samples[i].pid == pid) { previous = &proc_samples[i]; break; }
            if (!proc_samples[i].pid && !empty) empty = &proc_samples[i];
        }
        if (!previous) previous = empty;
        if (!previous) continue;
        unsigned long long delta = 0;
        unsigned long long sample_start = 0;
        if (previous->pid == pid && previous->start_ticks == start && ticks >= previous->cpu_ticks &&
            previous->sampled_ns && sampled_ns > previous->sampled_ns) {
            delta = ticks - previous->cpu_ticks;
            sample_start = previous->sampled_ns;
        }
        /* A new/reused PID establishes a baseline; do not invent an interval
         * from a differently quantized boot clock or charge a partial window. */
        *previous = (struct proc_cpu_sample){.pid=(unsigned int)pid, .start_ticks=start,
            .cpu_ticks=ticks, .sampled_ns=sampled_ns, .seen=true};
        size_t index;
        for (index = 0; index < *n && rows[index].pid != pid; ++index) {}
        if (index == *n) {
            if (*n == MAX_ROWS) continue;
            memset(&rows[index], 0, sizeof(rows[index]));
            rows[index].pid = pid;
            rows[index].stats.uid = info.st_uid;
            memcpy(rows[index].stats.comm, comm, sizeof(comm));
            ++*n;
        }
        rows[index].stats.runtime_ns = delta * 1000000000ULL / hz;
        rows[index].cpu_sample_start_ns = sample_start;
        rows[index].cpu_sample_end_ns = sampled_ns;
        rows[index].cpu_read_span_ns = read_end - read_begin;
        rows[index].process_start_ticks = start;
    }
    closedir(dir);
    for (size_t i = 0; i < MAX_ROWS; ++i)
        if (!proc_samples[i].seen) memset(&proc_samples[i], 0, sizeof(proc_samples[i]));
    return 0;
}
#endif
