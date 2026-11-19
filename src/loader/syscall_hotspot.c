#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "monitor_util.h"
#include "osmedic.h"
#include "syscall_hotspot.skel.h"

#define MAX_ROWS 4096

struct row {
    struct syscall_key key;
    struct syscall_stats value;
};

static const char *syscall_name(unsigned int id)
{
#ifdef SYS_openat
    if (id == SYS_openat) return "openat";
#endif
#ifdef SYS_newfstatat
    if (id == SYS_newfstatat) return "newfstatat";
#endif
#ifdef SYS_statx
    if (id == SYS_statx) return "statx";
#endif
#ifdef SYS_getpid
    if (id == SYS_getpid) return "getpid";
#endif
#ifdef SYS_read
    if (id == SYS_read) return "read";
#endif
#ifdef SYS_write
    if (id == SYS_write) return "write";
#endif
#ifdef SYS_close
    if (id == SYS_close) return "close";
#endif
    return "unknown";
}

static int by_calls_desc(const void *a, const void *b)
{
    const struct row *left = a, *right = b;
    return (right->value.calls > left->value.calls) -
           (right->value.calls < left->value.calls);
}

static int emit_window(int fd, FILE *out, double seconds, unsigned int top,
                       double baseline_rate, double min_rate,
                       const char *start, const char *end)
{
    struct row *rows = calloc(MAX_ROWS, sizeof(*rows));
    size_t n = 0;
    if (!rows)
        return -1;
    while (n < MAX_ROWS) {
        struct syscall_key key;
        if (bpf_map_get_next_key(fd, NULL, &key) != 0) {
            if (errno != ENOENT) goto fail;
            break;
        }
        if (bpf_map_lookup_and_delete_elem(fd, &key, &rows[n].value) == 0) {
            rows[n].key = key;
            ++n;
        } else if (errno != ENOENT) {
            goto fail;
        }
    }
    qsort(rows, n, sizeof(*rows), by_calls_desc);
    uint64_t ts_ns = monitor_now_ns(CLOCK_MONOTONIC);
    for (size_t i = 0; i < n && i < top; ++i) {
        struct row *r = &rows[i];
        double rate = r->value.calls / seconds;
        double mean_us = r->value.calls ?
            (double)r->value.total_ns / r->value.calls / 1000.0 : 0;
        unsigned long long p99 = monitor_p99(r->value.buckets,
                                              OSMEDIC_HIST_SLOTS,
                                              r->value.calls);
        r->value.comm[OSMEDIC_COMM_LEN - 1] = '\0';
        fprintf(out, "{\"scene\":\"syscall\",\"ts_ns\":%llu,\"pid\":%u,\"uid\":%u,\"comm\":",
                (unsigned long long)ts_ns, r->key.pid, r->value.uid);
        monitor_json_string(out, r->value.comm);
        fprintf(out, ",\"id\":%u,\"schema_version\":1,\"event\":\"syscall_metric\",\"window\":{\"start\":",
                r->key.syscall_id);
        monitor_json_string(out, start);
        fputs(",\"end\":", out);
        monitor_json_string(out, end);
        fputs("},\"syscall\":", out);
        monitor_json_string(out, syscall_name(r->key.syscall_id));
        fprintf(out, ",\"calls\":%llu,\"rate_per_sec\":%.2f,\"mean_us\":%.2f,\"p99_upper_us\":%llu}\n",
                r->value.calls, rate, mean_us, p99);
        if (rate < min_rate || rate < baseline_rate * 10.0)
            continue;
        fprintf(out, "{\"scene\":\"syscall\",\"ts_ns\":%llu,\"pid\":%u,\"uid\":%u,\"comm\":",
                (unsigned long long)ts_ns, r->key.pid, r->value.uid);
        monitor_json_string(out, r->value.comm);
        fprintf(out, ",\"id\":%u,\"schema_version\":1,\"event\":\"diagnosis\",\"type\":\"SYSCALL_HOTSPOT\",\"window\":{\"start\":",
                r->key.syscall_id);
        monitor_json_string(out, start);
        fputs(",\"end\":", out);
        monitor_json_string(out, end);
        fprintf(out, "},\"related_objects\":[{\"kind\":\"process\",\"pid\":%u,\"comm\":",
                r->key.pid);
        monitor_json_string(out, r->value.comm);
        fprintf(out, "},{\"kind\":\"syscall\",\"id\":%u,\"name\":",
                r->key.syscall_id);
        monitor_json_string(out, syscall_name(r->key.syscall_id));
        fprintf(out, "}],\"key_metrics\":{\"calls_per_sec\":%.2f,\"baseline_calls_per_sec\":%.2f,\"top_syscall_id\":%u,\"top_pid\":%u,\"mean_us\":%.2f,\"p99_upper_us\":%llu},",
                rate, baseline_rate, r->key.syscall_id, r->key.pid, mean_us, p99);
        fputs("\"suspected_root_cause\":\"进程频繁执行同一系统调用\",\"evidence_chain\":[\"该进程/系统调用组合进入当前窗口 Top-N\",\"调用频率超过配置基线的 10 倍\"],\"recommendation\":[\"检查高频调用路径并考虑批处理或缓存\"]}\n", out);
    }
    fflush(out);
    free(rows);
    return 0;
fail:
    fprintf(stderr, "读取 syscall map 失败: %s\n", strerror(errno));
    free(rows);
    return -1;
}

static int parse_positive(const char *arg, unsigned int *value)
{
    char *end;
    unsigned long n = strtoul(arg, &end, 10);
    if (!arg[0] || *end || n == 0 || n > 86400)
        return -1;
    *value = n;
    return 0;
}

int main(int argc, char **argv)
{
    static const struct option options[] = {
        {"output", required_argument, NULL, 'o'},
        {"interval", required_argument, NULL, 'i'},
        {"duration", required_argument, NULL, 'd'},
        {"top", required_argument, NULL, 't'},
        {"baseline-rate", required_argument, NULL, 'b'},
        {"min-rate", required_argument, NULL, 'm'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };
    const char *path = "-";
    unsigned int interval = 1, duration = 0, top = 10;
    double baseline_rate = 1000, min_rate = 1000;
    struct syscall_hotspot_bpf *skel = NULL;
    FILE *out = stdout;
    char start[48], end[48];
    uint64_t begin, last;
    int opt, result = 1;

    while ((opt = getopt_long(argc, argv, "o:i:d:t:b:m:h", options, NULL)) != -1) {
        char *endptr;
        switch (opt) {
        case 'o': path = optarg; break;
        case 'i': if (parse_positive(optarg, &interval)) return 2; break;
        case 'd': if (strcmp(optarg, "0") && parse_positive(optarg, &duration)) return 2; break;
        case 't': if (parse_positive(optarg, &top)) return 2; break;
        case 'b':
        case 'm': {
            double v = strtod(optarg, &endptr);
            if (!optarg[0] || *endptr || v <= 0 || v > 1000000000) return 2;
            if (opt == 'b') baseline_rate = v; else min_rate = v;
            break;
        }
        case 'h':
            fputs("syscall_hotspot [-o FILE|-] [-i SEC] [-d SEC] [-t TOP] [--baseline-rate CALLS/S] [--min-rate CALLS/S]\n", stderr);
            return 0;
        default: return 2;
        }
    }
    if (optind != argc || top > MAX_ROWS) return 2;
    if (strcmp(path, "-")) {
        out = fopen(path, "a");
        if (!out) { perror(path); return 1; }
    }
    signal(SIGINT, monitor_signal);
    signal(SIGTERM, monitor_signal);
    skel = syscall_hotspot_bpf__open();
    if (!skel) goto done;
    skel->rodata->ignored_pid = getpid();
    if (syscall_hotspot_bpf__load(skel) || syscall_hotspot_bpf__attach(skel)) {
        fputs("无法加载或挂载 syscall raw tracepoint（需要 root 和内核 BTF）。\n", stderr);
        goto done;
    }
    fprintf(stderr, "syscall_hotspot 已启动；每 %u 秒汇总，基线 %.0f 次/秒。\n", interval, baseline_rate);
    begin = last = monitor_now_ns(CLOCK_MONOTONIC);
    monitor_timestamp(start, sizeof(start));
    while (!monitor_stop) {
        uint64_t now;
        monitor_wait_until(last + (uint64_t)interval * 1000000000ULL);
        now = monitor_now_ns(CLOCK_MONOTONIC);
        if (now <= last) break;
        monitor_timestamp(end, sizeof(end));
        if (emit_window(bpf_map__fd(skel->maps.syscall_totals), out,
                        (now - last) / 1e9, top, baseline_rate, min_rate,
                        start, end)) goto done;
        last = now;
        memcpy(start, end, sizeof(start));
        if (duration && now - begin >= (uint64_t)duration * 1000000000ULL)
            break;
    }
    result = 0;
done:
    syscall_hotspot_bpf__destroy(skel);
    if (out != stdout) fclose(out);
    return result;
}
