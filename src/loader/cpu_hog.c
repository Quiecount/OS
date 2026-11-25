#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "cpu_hog.skel.h"
#include "monitor_util.h"
#include "osmedic.h"
#include "cpu_rules.h"

#define MAX_ROWS 4096

#include "window_merge.h"

#include "proc_cpu.h"

struct streak {
    unsigned int pid;
    double seconds;
    unsigned long long start_ticks;
    bool seen;
};

static struct streak streaks[MAX_ROWS];

static struct streak *find_streak(unsigned int pid)
{
    struct streak *free_slot = NULL;
    for (size_t i = 0; i < MAX_ROWS; ++i) {
        if (streaks[i].pid == pid) return &streaks[i];
        if (!streaks[i].pid && !free_slot) free_slot = &streaks[i];
    }
    if (free_slot) free_slot->pid = pid;
    return free_slot;
}

static int by_runtime_desc(const void *a, const void *b)
{
    const struct cpu_row *left = a, *right = b;
    return (right->stats.runtime_ns > left->stats.runtime_ns) -
           (right->stats.runtime_ns < left->stats.runtime_ns);
}

static void emit_cpu_hog(FILE *out, const struct cpu_row *r, double cpu_pct,
                         double streak, const char *start, const char *end)
{
    fprintf(out, "{\"scene\":\"cpu\",\"ts_ns\":%llu,\"pid\":%u,\"uid\":%u,\"comm\":",
            (unsigned long long)monitor_now_ns(CLOCK_MONOTONIC), r->pid, r->stats.uid);
    monitor_json_string(out, r->stats.comm);
    fputs(",\"schema_version\":1,\"event\":\"diagnosis\",\"type\":\"CPU_HOG\",\"window\":{\"start\":", out);
    monitor_json_string(out, start);
    fputs(",\"end\":", out);
    monitor_json_string(out, end);
    fprintf(out, "},\"related_objects\":[{\"kind\":\"process\",\"pid\":%u,\"comm\":",
            r->pid);
    monitor_json_string(out, r->stats.comm);
    fprintf(out, "}],\"key_metrics\":{\"cpu_percent\":%.2f,\"pid\":%u,\"duration_over_80_percent_s\":%.2f},",
            cpu_pct, r->pid, streak);
    fputs("\"suspected_root_cause\":\"进程持续占用超过单核容量的 80%\",\"evidence_chain\":[\"/proc 累计 CPU 时间的窗口差值超过单核 80%\",\"持续时间达到 10 秒\"],\"recommendation\":[\"检查热点线程和计算循环\"]}\n", out);
}

static void emit_sched_delay(FILE *out, unsigned long long p99,
                             unsigned long long samples,
                             unsigned long long baseline_us,
                             const struct cpu_row *top_waiter,
                             const char *start, const char *end)
{
    fprintf(out, "{\"scene\":\"cpu\",\"ts_ns\":%llu,\"pid\":%u,\"uid\":%u,\"comm\":",
            (unsigned long long)monitor_now_ns(CLOCK_MONOTONIC),
            top_waiter->pid, top_waiter->stats.uid);
    monitor_json_string(out, top_waiter->stats.comm);
    fputs(",\"schema_version\":1,\"event\":\"diagnosis\",\"type\":\"SCHED_DELAY\",\"window\":{\"start\":", out);
    monitor_json_string(out, start);
    fputs(",\"end\":", out);
    monitor_json_string(out, end);
    fprintf(out, "},\"related_objects\":[{\"kind\":\"process\",\"pid\":%u,\"comm\":",
            top_waiter->pid);
    monitor_json_string(out, top_waiter->stats.comm);
    fprintf(out, "}],\"key_metrics\":{\"runqlat_p99_ns\":%llu,\"baseline_p99_ns\":%llu,\"samples\":%llu,\"over_threshold_samples\":%llu,\"threshold_ns\":%llu},",
            p99 * 1000, baseline_us * 1000, samples,
            top_waiter->stats.runq_over_threshold, baseline_us * 5000);
    fputs("\"suspected_root_cause\":\"CPU 运行队列等待显著升高\",\"evidence_chain\":[\"该进程 sched_wakeup/sched_switch 等待时间 P99 超过配置基线的 5 倍\",\"窗口内至少有 20 次等待样本\"],\"recommendation\":[\"检查 CPU 饱和及高优先级线程\"]}\n", out);
}

static int emit_window(int fd, FILE *out, unsigned int top,
                       unsigned long long baseline_us,
                       const char *start, const char *end)
{
    struct cpu_row *rows = calloc(MAX_ROWS, sizeof(*rows));
    unsigned long long global_buckets[OSMEDIC_RUNQ_SLOTS] = {};
    unsigned long long global_samples = 0;
    size_t n = 0;
    if (!rows) return -1;
    for (size_t i = 0; i < MAX_ROWS; ++i) streaks[i].seen = false;
    while (n < MAX_ROWS) {
        unsigned int pid;
        if (bpf_map_get_next_key(fd, NULL, &pid) != 0) {
            if (errno != ENOENT) goto fail;
            break;
        }
        if (bpf_map_lookup_and_delete_elem(fd, &pid, &rows[n].stats) == 0) {
            rows[n].pid = pid;
            ++n;
        } else if (errno != ENOENT) goto fail;
    }
    n = merge_cpu_rows(rows, n);
    if (sample_process_cpu(rows, &n)) goto fail;
    qsort(rows, n, sizeof(*rows), by_runtime_desc);
    for (size_t i = 0; i < n; ++i) {
        struct cpu_row *r = &rows[i];
        double cpu_pct = cpu_interval_percent(r->stats.runtime_ns,
                                              r->cpu_sample_start_ns, r->cpu_sample_end_ns);
        double sample_seconds = r->cpu_sample_start_ns && r->cpu_sample_end_ns > r->cpu_sample_start_ns ?
            (r->cpu_sample_end_ns - r->cpu_sample_start_ns) / 1e9 : 0;
        unsigned long long p99 = monitor_p99(r->stats.runq_buckets,
                                              OSMEDIC_RUNQ_SLOTS,
                                              r->stats.runq_samples);
        struct streak *s = find_streak(r->pid);
        r->stats.comm[OSMEDIC_COMM_LEN - 1] = '\0';
        for (unsigned int j = 0; j < OSMEDIC_RUNQ_SLOTS; ++j)
            global_buckets[j] += r->stats.runq_buckets[j];
        global_samples += r->stats.runq_samples;
        if (s) {
            s->seen = true;
            if (s->start_ticks != r->process_start_ticks) s->seconds = 0;
            s->start_ticks = r->process_start_ticks;
            if (cpu_pct > 80.0) s->seconds += sample_seconds;
            else s->seconds = 0;
        }
        if (i < top) {
            fprintf(out, "{\"scene\":\"cpu\",\"ts_ns\":%llu,\"pid\":%u,\"uid\":%u,\"comm\":",
                    (unsigned long long)monitor_now_ns(CLOCK_MONOTONIC), r->pid, r->stats.uid);
            monitor_json_string(out, r->stats.comm);
            fputs(",\"schema_version\":1,\"event\":\"cpu_metric\",\"window\":{\"start\":", out);
            monitor_json_string(out, start);
            fputs(",\"end\":", out);
            monitor_json_string(out, end);
            fprintf(out, "},\"cpu_sample_start_ns\":%llu,\"cpu_sample_end_ns\":%llu,\"cpu_read_span_ns\":%llu,\"cpu_sample_valid\":%s,\"runq_over_threshold_samples\":%llu,\"runq_threshold_ns\":%llu",
                    r->cpu_sample_start_ns, r->cpu_sample_end_ns, r->cpu_read_span_ns,
                    sample_seconds > 0 ? "true" : "false", r->stats.runq_over_threshold, baseline_us * 5000);
            fprintf(out, ",\"cpu_percent_one_core\":%.2f,\"offcpu_completed_ms\":%.3f,\"offcpu_completed_samples\":%llu,\"runq_wait_ms\":%.3f,\"runq_samples\":%llu,\"runq_p99_upper_us\":%llu,\"histogram\":\"log2_8_ns\",\"runq_p99_overflow\":%s,\"runq_buckets\":[",
                    cpu_pct, r->stats.offcpu_total_ns / 1e6, r->stats.offcpu_samples,
                    r->stats.runq_total_ns / 1e6, r->stats.runq_samples, p99,
                    r->stats.runq_buckets[OSMEDIC_RUNQ_SLOTS - 1] > r->stats.runq_samples / 100 ? "true" : "false");
            for (unsigned int j = 0; j < OSMEDIC_RUNQ_SLOTS; ++j)
                fprintf(out, "%s%llu", j ? "," : "", r->stats.runq_buckets[j]);
            fputs("]}\n", out);
        }
        if (runq_p99_exceeds(r->stats.runq_samples, r->stats.runq_over_threshold))
            emit_sched_delay(out, p99, r->stats.runq_samples, baseline_us, r, start, end);
        if (s && s->seconds >= 10.0 && cpu_pct > 80.0)
            emit_cpu_hog(out, r, cpu_pct, s->seconds, start, end);
    }
    for (size_t i = 0; i < MAX_ROWS; ++i)
        if (streaks[i].pid && !streaks[i].seen)
            memset(&streaks[i], 0, sizeof(streaks[i]));
    unsigned long long p99 = monitor_p99(global_buckets, OSMEDIC_RUNQ_SLOTS,
                                          global_samples);
    fprintf(out, "{\"scene\":\"cpu\",\"ts_ns\":%llu,\"pid\":0,\"uid\":0,\"comm\":\"scheduler\",\"schema_version\":1,\"event\":\"scheduler_metric\",\"window\":{\"start\":",
            (unsigned long long)monitor_now_ns(CLOCK_MONOTONIC));
    monitor_json_string(out, start);
    fputs(",\"end\":", out);
    monitor_json_string(out, end);
    fprintf(out, "},\"runq_samples\":%llu,\"runq_p99_upper_us\":%llu}\n",
            global_samples, p99);
    fflush(out);
    free(rows);
    return 0;
fail:
    fprintf(stderr, "读取 CPU map 失败: %s\n", strerror(errno));
    free(rows);
    return -1;
}

static int parse_positive(const char *arg, unsigned int *out)
{
    char *end;
    unsigned long n = strtoul(arg, &end, 10);
    if (!arg[0] || *end || n == 0 || n > 86400) return -1;
    *out = n;
    return 0;
}

int main(int argc, char **argv)
{
    static const struct option options[] = {
        {"output", required_argument, NULL, 'o'},
        {"interval", required_argument, NULL, 'i'},
        {"duration", required_argument, NULL, 'd'},
        {"top", required_argument, NULL, 't'},
        {"baseline-p99-us", required_argument, NULL, 'b'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };
    const char *path = "-";
    unsigned int interval = 1, duration = 0, top = 10, baseline = 1000;
    struct cpu_hog_bpf *skel = NULL;
    FILE *out = stdout;
    char start[48], end[48];
    uint64_t begin, last;
    int opt, result = 1;
    while ((opt = getopt_long(argc, argv, "o:i:d:t:b:h", options, NULL)) != -1) {
        switch (opt) {
        case 'o': path = optarg; break;
        case 'i': if (parse_positive(optarg, &interval)) return 2; break;
        case 'd': if (strcmp(optarg, "0") && parse_positive(optarg, &duration)) return 2; break;
        case 't': if (parse_positive(optarg, &top)) return 2; break;
        case 'b': if (parse_positive(optarg, &baseline)) return 2; break;
        case 'h':
            fputs("cpu_hog [-o FILE|-] [-i SEC] [-d SEC] [-t TOP] [--baseline-p99-us US]\n", stderr);
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
    skel = cpu_hog_bpf__open();
    if (!skel) goto done;
    skel->rodata->ignored_pid = getpid();
    skel->rodata->runq_threshold_ns = (unsigned long long)baseline * 5000;
    if (cpu_hog_bpf__load(skel) || cpu_hog_bpf__attach(skel)) {
        fputs("无法加载或挂载 sched tracepoint（需要 root、BTF 和 sched_switch/sched_wakeup）。\n", stderr);
        goto done;
    }
    fprintf(stderr, "cpu_hog 已启动；每 %u 秒汇总，runqlat P99 基线 %u us。\n",
            interval, baseline);
    begin = last = monitor_now_ns(CLOCK_MONOTONIC);
    struct cpu_row *initial = calloc(MAX_ROWS, sizeof(*initial));
    size_t initial_count = 0;
    if (!initial) goto done;
    int sampled = sample_process_cpu(initial, &initial_count);
    free(initial);
    if (sampled) goto done;
    monitor_timestamp(start, sizeof(start));
    while (!monitor_stop) {
        uint64_t now;
        monitor_wait_until(last + (uint64_t)interval * 1000000000ULL);
        now = monitor_now_ns(CLOCK_MONOTONIC);
        if (now <= last) break;
        monitor_timestamp(end, sizeof(end));
        if (emit_window(bpf_map__fd(skel->maps.cpu_totals), out,
                        top, baseline, start, end)) goto done;
        last = now;
        memcpy(start, end, sizeof(start));
        if (duration && now - begin >= (uint64_t)duration * 1000000000ULL)
            break;
    }
    result = 0;
done:
    cpu_hog_bpf__destroy(skel);
    if (out != stdout) fclose(out);
    return result;
}
