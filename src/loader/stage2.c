/* 场景 3–5 共用采集生命周期、窗口聚合、JSON 和错误处理。
 * 编译时以 OSMEDIC_NAME 选择场景；未选中的探针不会打开或挂载。 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include "stage2.h"
#include "monitor_util.h"
#include "json_output.h"
#include "io_latency.skel.h"
#include "mem_pressure.skel.h"
#include "lock_contention.skel.h"

#define STACK_SAMPLES 16
struct row {
    bool used;
    struct ev_common c;
    unsigned long long generation, address, discriminator;
    unsigned long long samples, total, bytes, errors, peak, above, offcpu;
    unsigned long long eagain, timeouts, interrupted, stack_errors;
    unsigned long long buckets[OSMEDIC_FINE_SLOTS];
    unsigned int op;
    char disk[32];
    struct { int id; unsigned int count; } stack[STACK_SAMPLES];
    unsigned int nstacks, tids[STACK_SAMPLES], ntids;
    unsigned long long stack_unrepresented, tid_unrepresented;
};
struct mem_previous {
    bool used, rss_valid;
    struct p2_process key;
    struct p2_mem_stats value;
    unsigned long long rss, sampled_ns;
};
static struct row *rows;
static struct mem_previous *previous;
static struct io_latency_bpf *io;
static struct mem_pressure_bpf *mem;
static struct lock_contention_bpf *lock;
static FILE *out;
static bool pretty, histogram;
static const char *scene;
static char start[48], end[48];
static unsigned int duration, interval = 1, pid_filter, min_waiters = 3;
static double baseline_io_us = 1000, baseline_faults = 1000, wait_ms = 100;
static unsigned long long aggregation_dropped;
static int cpus;
static unsigned long long now_ns;
static void emit_stacks(const struct row *r);
static const struct row *diagnosis_lock;

static int positive(const char *text, unsigned int *number, unsigned long max, bool zero)
{
    char *tail;
    errno = 0;
    if (!text[0] || text[0] < '0' || text[0] > '9') return -1;
    unsigned long n = strtoul(text, &tail, 10);
    if (errno || *tail || n > max || (!n && !zero)) return -1;
    *number = n;
    return 0;
}
static int threshold(const char *s, double *number)
{
    char *tail;
    errno = 0;
    double value = strtod(s, &tail);
    if (!s[0] || *tail || errno || !isfinite(value) || value <= 0 || value > 1e12) return -1;
    *number = value;
    return 0;
}
static void prefix(const struct ev_common *c, unsigned long long generation, const char *event)
{
    fprintf(out, "{\"scene\":\"%s\",\"ts_ns\":%llu,\"pid\":%u,\"uid\":%u,\"comm\":",
            scene, now_ns, c->pid, c->uid);
    write_json_string(out, c->comm, sizeof(c->comm));
    fprintf(out, ",\"process_start_ns\":%llu,\"event\":\"%s\",\"window\":{\"start\":", generation, event);
    write_json_string(out, start, sizeof(start));
    fputs(",\"end\":", out); write_json_string(out, end, sizeof(end)); fputc('}', out);
}
static void diagnosis(const struct ev_common *c, unsigned long long generation,
                      const char *type, const char *metrics, const char *related,
                      const char *cause, const char *evidence, const char *advice)
{
    if (pretty) {
        fprintf(out, "ALERT %-16s pid=%u ", type, c->pid);
        write_json_string(out, c->comm, sizeof(c->comm)); fprintf(out, " %s\n", metrics); return;
    }
    prefix(c, generation, "diagnosis");
    fprintf(out, ",\"type\":\"%s\",\"key_metrics\":{%s", type, metrics);
    if (diagnosis_lock) emit_stacks(diagnosis_lock);
    fprintf(out, "},\"related_objects\":[{\"kind\":\"process\",\"pid\":%u}%s]", c->pid, related);
    fputs(",\"suspected_root_cause\":", out);
    write_json_string(out, cause, strlen(cause)); fputs(",\"evidence_chain\":[", out);
    write_json_string(out, evidence, strlen(evidence)); fputs("],\"recommendation\":[", out);
    write_json_string(out, advice, strlen(advice)); fputs("]}\n", out);
}
static struct row *find_row(const struct ev_common *c, unsigned long long generation,
                            unsigned long long address, unsigned long long discriminator)
{
    unsigned long long hash = (generation ^ address ^ ((unsigned long long)c->pid << 32) ^ discriminator) * 11400714819323198485ULL;
    for (unsigned int i = 0; i < P2_ROWS; i++) {
        struct row *r = &rows[(hash + i) % P2_ROWS];
        if (!r->used) {
            r->used = true; r->c = *c; r->generation = generation;
            r->address = address; r->discriminator = discriminator; return r;
        }
        if (r->c.pid == c->pid && r->generation == generation &&
            r->address == address && r->discriminator == discriminator) return r;
    }
    aggregation_dropped++; return NULL;
}
static void sample(struct row *r, unsigned long long ns)
{
    r->samples++; r->total += ns; r->buckets[latency_bucket(ns)]++;
}
static int io_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size != sizeof(struct ev_io)) return -EINVAL;
    const struct ev_io *e = data;
    struct row *r = find_row(&e->c, e->process_start_ns,
                             ((unsigned long long)e->major << 32) | e->minor, e->operation);
    if (!r) return 0;
    sample(r, e->delta_ns); r->bytes += e->bytes; r->errors += !!e->error;
    r->above += e->delta_ns > baseline_io_us * 5000.0;
    if (e->queue_depth > r->peak) r->peak = e->queue_depth;
    r->op = e->operation; memcpy(r->disk, e->disk, sizeof(r->disk)); return 0;
}
static int lock_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size != sizeof(struct ev_lock)) return -EINVAL;
    const struct ev_lock *e = data;
    struct row *r = find_row(&e->c, e->process_start_ns, e->uaddr, e->op);
    if (!r) return 0;
    r->op = e->op;
    if (e->ret == -EAGAIN) { r->eagain++; return 0; }
    if (e->ret && e->ret != -ETIMEDOUT && e->ret != -EINTR && e->ret != -512 && e->ret != -516) {
        r->errors++; return 0;
    }
    r->timeouts += e->ret == -ETIMEDOUT;
    r->interrupted += e->ret == -EINTR || e->ret == -512 || e->ret == -516;
    sample(r, e->wait_ns); r->offcpu += e->offcpu_ns;
    if (e->waiter_count > r->peak) r->peak = e->waiter_count;
    unsigned int i;
    for (i = 0; i < r->ntids; i++) if (r->tids[i] == e->tid) break;
    if (i == r->ntids) {
        if (r->ntids < STACK_SAMPLES) r->tids[r->ntids++] = e->tid;
        else r->tid_unrepresented++;
    }
    if (e->stack_id < 0) { r->stack_errors++; return 0; }
    for (i = 0; i < r->nstacks; i++) if (r->stack[i].id == e->stack_id) break;
    if (i == r->nstacks) {
        if (i == STACK_SAMPLES) { r->stack_unrepresented++; return 0; }
        r->stack[i].id = e->stack_id; r->nstacks++;
    }
    r->stack[i].count++; return 0;
}
static int oom_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size != sizeof(struct ev_mem)) return -EINVAL;
    const struct ev_mem *e = data;
    char metrics[96];
    now_ns = e->c.ts_ns;
    monitor_timestamp(end, sizeof(end));
    snprintf(metrics, sizeof(metrics), "\"victim_pid\":%u,\"identity_known\":false", e->c.pid);
    if (!pretty) { prefix(&e->c, 0, "oom"); fprintf(out, ",\"addr\":\"0x0\",\"identity_known\":false,\"oom_ts_ns\":%llu}\n", e->c.ts_ns); }
    diagnosis(&e->c, 0, "OOM_KILL", metrics, "", "内核标记了 OOM victim；身份元数据未知",
              "oom:mark_victim 提供了被选中的 victim PID", "检查进程内存需求及所属 cgroup 限额；区分 cgroup OOM 与全机 OOM");
    return ferror(out) ? -EIO : 0;
}
static void emit_histogram(const struct row *r)
{
    fprintf(out, ",\"histogram\":\"log2_8_ns\",\"p99_overflow\":%s",
            r->buckets[OSMEDIC_FINE_SLOTS - 1] > r->samples / 100 ? "true" : "false");
    if (!histogram) return;
    fputs(",\"latency_buckets\":[", out);
    for (unsigned int i = 0; i < OSMEDIC_FINE_SLOTS; i++) fprintf(out, "%s%llu", i ? "," : "", r->buckets[i]);
    fputc(']', out);
}
static void emit_stacks(const struct row *r)
{
    unsigned long long frames[P2_STACK_DEPTH];
    fprintf(out, ",\"stack_error_samples\":%llu,\"stack_unrepresented_samples\":%llu,\"tid_unrepresented_samples\":%llu,\"tids\":[",
            r->stack_errors, r->stack_unrepresented, r->tid_unrepresented);
    for (unsigned int i = 0; i < r->ntids; i++) fprintf(out, "%s%u", i ? "," : "", r->tids[i]);
    fputs("],\"stacks\":[", out);
    for (unsigned int i = 0; i < r->nstacks; i++) {
        int found = bpf_map_lookup_elem(bpf_map__fd(lock->maps.stacks), &r->stack[i].id, frames);
        fprintf(out, "%s{\"stack_id\":%d,\"count\":%u,\"available\":%s,\"frames\":[",
                i ? "," : "", r->stack[i].id, r->stack[i].count, found ? "false" : "true");
        if (!found) for (unsigned int j = 0; j < P2_STACK_DEPTH && frames[j]; j++)
            fprintf(out, "%s\"0x%llx\"", j ? "," : "", frames[j]);
        fputs("]}", out);
    }
    fputc(']', out);
}
static int emit_rows(double seconds, bool incomplete)
{
    for (unsigned int i = 0; i < P2_ROWS; i++) {
        struct row *r = &rows[i];
        if (!r->used) continue;
        unsigned long long p99 = monitor_p99(r->buckets, OSMEDIC_FINE_SLOTS, r->samples) * 1000;
        char metrics[1024], related[256];
        if (io) {
            snprintf(metrics, sizeof(metrics), "\"p99_ns\":%llu,\"baseline_p99_ns\":%.0f,\"iops\":%.3f,\"device\":\"%u:%u\",\"samples\":%llu,\"over_threshold_samples\":%llu",
                     p99, baseline_io_us * 1000, r->samples / seconds,
                     (unsigned int)(r->address >> 32), (unsigned int)r->address, r->samples, r->above);
            snprintf(related, sizeof(related), ",{\"kind\":\"device\",\"name\":\"%u:%u\"}", (unsigned int)(r->address >> 32), (unsigned int)r->address);
            if (pretty) fprintf(out, "IO   pid=%u dev=%u:%u %-5s n=%llu mean_ns=%llu p99_ns=%llu q=%llu\n",
                                r->c.pid, (unsigned int)(r->address >> 32), (unsigned int)r->address, r->op ? "write" : "read", r->samples, r->samples ? r->total / r->samples : 0, p99, r->peak);
            else {
                prefix(&r->c, r->generation, "io_metric"); fprintf(out, ",%s,\"operation\":\"%s\",\"bytes\":%llu,\"mean_ns\":%llu,\"errors\":%llu,\"queue_depth_observed_max\":%llu,\"disk\":",
                    metrics, r->op ? "write" : "read", r->bytes, r->samples ? r->total / r->samples : 0, r->errors, r->peak);
                write_json_string(out, r->disk, sizeof(r->disk)); emit_histogram(r); fprintf(out, ",\"window_incomplete\":%s}\n", incomplete ? "true" : "false");
            }
            if (!incomplete && r->op == 1 && r->samples >= 20 && r->above > r->samples / 100)
                diagnosis(&r->c, r->generation, "IO_JITTER", metrics, related, "该进程下发的写请求延迟尾部超过配置基线", "同进程、同设备至少20个完成请求；精确超阈值计数满足 P99 判定", "核查设备负载、限流及业务时延；下发者可能是内核回写线程，不能直接推断文件归属");
        } else {
            snprintf(metrics, sizeof(metrics), "\"wait_ns_total\":%llu,\"waiter_count\":%llu,\"uaddr\":\"0x%llx\",\"samples\":%llu,\"p99_ns\":%llu", r->total, r->peak, r->address, r->samples, p99);
            snprintf(related, sizeof(related), ",{\"kind\":\"lock\",\"uaddr\":\"0x%llx\"}", r->address);
            if (pretty) fprintf(out, "LOCK pid=%u uaddr=0x%llx n=%llu wait_ns=%llu waiters=%llu EAGAIN=%llu\n", r->c.pid, r->address, r->samples, r->total, r->peak, r->eagain);
            else {
                prefix(&r->c, r->generation, "lock_metric"); fprintf(out, ",%s,\"op\":%u,\"mean_ns\":%llu,\"offcpu_ns_total\":%llu,\"eagain\":%llu,\"timeouts\":%llu,\"interrupted\":%llu,\"other_errors\":%llu",
                    metrics, r->op, r->samples ? r->total / r->samples : 0, r->offcpu, r->eagain, r->timeouts, r->interrupted, r->errors);
                emit_histogram(r); emit_stacks(r); fprintf(out, ",\"window_incomplete\":%s}\n", incomplete ? "true" : "false");
            }
            if (!incomplete && r->peak >= min_waiters && r->total > wait_ms * 1e6) {
                diagnosis_lock = r;
                diagnosis(&r->c, r->generation, "LOCK_CONTENTION", metrics, related, "同一地址空间的 futex WAIT 出现并发等待", "并发 WAIT 数及完成等待总时长超过配置阈值；调用栈见同窗口同锁 lock_metric", "检查同窗口 lock_metric.stacks/tids；区分互斥锁、条件变量及正常 join 等待");
                diagnosis_lock = NULL;
            }
        }
    }
    memset(rows, 0, P2_ROWS * sizeof(*rows)); return ferror(out) ? -1 : 0;
}
/* RSS 只在仍是同一进程实例时读取。start_boottime 与 /proc starttime 同源，后者按 tick 截断。 */
static bool read_rss(const struct p2_process *key, unsigned long long *rss)
{
    char path[64], line[4096];
    unsigned long long ticks = 0, resident, size;
    snprintf(path, sizeof(path), "/proc/%u", key->pid);
    int dir = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) return false;
    int stat_fd = openat(dir, "stat", O_RDONLY | O_CLOEXEC);
    if (stat_fd < 0) { close(dir); return false; }
    FILE *f = fdopen(stat_fd, "r");
    if (!f) { close(stat_fd); close(dir); return false; }
    bool ok = fgets(line, sizeof(line), f) != NULL; fclose(f);
    char *p = ok ? strrchr(line, ')') : NULL;
    if (!p) { close(dir); return false; }
    p += 2;
    for (int field = 3; field <= 22; field++) {
        char *next = strchr(p, ' ');
        if (field == 22) { ticks = strtoull(p, NULL, 10); break; }
        if (!next) { close(dir); return false; }
        p = next + 1;
    }
    long hz = sysconf(_SC_CLK_TCK), page_size = sysconf(_SC_PAGESIZE);
    if (hz <= 0 || page_size <= 0 || ticks != key->start_ns / (1000000000ULL / hz)) { close(dir); return false; }
    int rss_fd = openat(dir, "statm", O_RDONLY | O_CLOEXEC);
    close(dir);
    if (rss_fd < 0) return false;
    f = fdopen(rss_fd, "r");
    if (!f) { close(rss_fd); return false; }
    ok = fscanf(f, "%llu %llu", &size, &resident) == 2; fclose(f);
    if (ok) *rss = resident * page_size;
    return ok;
}
static int emit_memory(double seconds, bool incomplete)
{
    struct p2_process key = {}, next;
    bool have_key = false;
    struct p2_mem_stats *values = calloc(cpus, sizeof(*values));
    if (!values) return -1;
    int fd = bpf_map__fd(mem->maps.totals), result = -1;
    unsigned int visited = 0;
    while (bpf_map_get_next_key(fd, have_key ? &key : NULL, &next) == 0) {
        key = next; have_key = true;
        if (++visited > P2_ROWS) { errno = EOVERFLOW; goto done; }
        if (bpf_map_lookup_elem(fd, &key, values)) { if (errno == ENOENT) continue; goto done; }
        struct p2_mem_stats total = {};
        for (int cpu = 0; cpu < cpus; cpu++) {
            total.faults += values[cpu].faults; total.mmap_calls += values[cpu].mmap_calls;
            total.mmap_bytes += values[cpu].mmap_bytes; total.mmap_failures += values[cpu].mmap_failures;
            if (values[cpu].c.ts_ns >= total.c.ts_ns) { total.c = values[cpu].c; total.addr = values[cpu].addr; }
        }
        struct mem_previous *prev = NULL;
        for (unsigned int i = 0; i < P2_ROWS; i++) {
            if (!previous[i].used || !memcmp(&previous[i].key, &key, sizeof(key))) { prev = &previous[i]; break; }
        }
        if (!prev) { aggregation_dropped++; continue; }
        unsigned long long faults = total.faults - prev->value.faults;
        unsigned long long calls = total.mmap_calls - prev->value.mmap_calls;
        unsigned long long bytes = total.mmap_bytes - prev->value.mmap_bytes;
        unsigned long long failures = total.mmap_failures - prev->value.mmap_failures;
        unsigned long long rss = 0;
        bool rss_valid = read_rss(&key, &rss);
        bool growth_valid = rss_valid && prev->rss_valid && now_ns > prev->sampled_ns;
        double growth = growth_valid ? ((long long)rss - (long long)prev->rss) / ((now_ns - prev->sampled_ns) / 1e9) : 0;
        *prev = (struct mem_previous){true, rss_valid, key, total, rss, now_ns};
        if (!faults && !calls && !failures && !rss_valid) continue;
        if (pretty) fprintf(out, "MEM  pid=%u faults/s=%.2f mmap=%llu failures=%llu RSS=%s%llu\n", key.pid, faults / seconds, calls, failures, rss_valid ? "" : "unknown:", rss);
        else {
            prefix(&total.c, key.start_ns, "mem_metric");
            fprintf(out, ",\"addr\":\"0x%llx\",\"faults\":%llu,\"faults_per_sec\":%.3f,\"large_mmap_calls\":%llu,\"large_mmap_bytes\":%llu,\"large_mmap_failures\":%llu,\"rss_valid\":%s,\"rss_bytes\":",
                total.addr, faults, faults / seconds, calls, bytes, failures, rss_valid ? "true" : "false");
            if (rss_valid) fprintf(out, "%llu", rss); else fputs("null", out);
            fprintf(out, ",\"rss_growth_valid\":%s,\"rss_growth_bytes_per_sec\":", growth_valid ? "true" : "false");
            if (growth_valid) fprintf(out, "%.3f", growth); else fputs("null", out);
            fprintf(out, ",\"window_incomplete\":%s}\n", incomplete ? "true" : "false");
        }
        if (!incomplete && faults / seconds > baseline_faults * 5) {
            char metrics[256];
            snprintf(metrics, sizeof(metrics), "\"faults_per_sec\":%.3f,\"baseline_faults_per_sec\":%.3f,\"top_pid\":%u", faults / seconds, baseline_faults, key.pid);
            diagnosis(&total.c, key.start_ns, "MEM_PRESSURE", metrics, "", "进程用户态缺页率超过配置基线", "用户态缺页异常计数；大块 mmap/RSS 见同窗口 mem_metric，不能仅凭缺页率断言物理内存耗尽", "检查工作集变化、mmap 行为和 cgroup 内存限额");
        }
    }
    result = errno == ENOENT ? 0 : -1;
done:
    free(values); return result;
}
static int emit_window(double seconds)
{
    unsigned long long tracking = io ? io->bss->tracking_failures : mem ? mem->bss->tracking_failures : lock->bss->tracking_failures;
    unsigned long long dropped = io ? io->bss->ringbuf_dropped : mem ? mem->bss->ringbuf_dropped : lock->bss->ringbuf_dropped;
    /* 任何历史丢失都可能污染未完成配对，保守抑制本次运行余下的阈值告警。 */
    bool incomplete = tracking || dropped || aggregation_dropped;
    if (mem ? emit_memory(seconds, incomplete) : emit_rows(seconds, incomplete)) return -1;
    incomplete = incomplete || aggregation_dropped;
    if (pretty) fprintf(out, "HEALTH tracking_failures=%llu ringbuf_dropped=%llu aggregation_dropped=%llu incomplete=%u\n", tracking, dropped, aggregation_dropped, incomplete);
    else {
        struct ev_common c = {.comm = "monitor"};
        prefix(&c, 0, "telemetry");
        fprintf(out, ",\"tracking_failures\":%llu,\"ringbuf_dropped\":%llu,\"aggregation_dropped\":%llu,\"window_incomplete\":%s",
                tracking, dropped, aggregation_dropped, incomplete ? "true" : "false");
        if (io) fprintf(out, ",\"partial_completions\":%llu,\"requeues\":%llu,\"active_requests\":%llu", io->bss->partial_completions, io->bss->requeues, io->bss->active_requests);
        if (lock) fprintf(out, ",\"active_waits\":%llu", lock->bss->active_waits);
        fputs("}\n", out);
    }
    return fflush(out) || ferror(out) ? -1 : 0;
}
int main(int argc, char **argv)
{
    static const struct option opts[] = {
        {"duration", required_argument, NULL, 'd'}, {"interval", required_argument, NULL, 'i'},
        {"output", required_argument, NULL, 'o'}, {"pid", required_argument, NULL, 'p'},
        {"pretty", no_argument, NULL, 'P'}, {"histogram", no_argument, NULL, 'H'},
        {"baseline-p99-us", required_argument, NULL, 'b'}, {"baseline-faults", required_argument, NULL, 'f'},
        {"min-waiters", required_argument, NULL, 'n'}, {"wait-ms", required_argument, NULL, 'w'},
        {"help", no_argument, NULL, 'h'}, {0, 0, 0, 0}
    };
    const char *path = "-";
    int opt, result = 1, event_fd = -1;
    struct ring_buffer *ring = NULL;
    ring_buffer_sample_fn callback;
    out = stdout;
    scene = !strcmp(OSMEDIC_NAME, "io_latency") ? "io" : !strcmp(OSMEDIC_NAME, "mem_pressure") ? "mem" : "lock";
    while ((opt = getopt_long(argc, argv, "d:i:o:p:PHb:f:n:w:h", opts, NULL)) != -1) {
        switch (opt) {
        case 'd': if (positive(optarg, &duration, 86400, true)) goto usage; break;
        case 'i': if (positive(optarg, &interval, 86400, false)) goto usage; break;
        case 'o': path = optarg; break;
        case 'p': if (positive(optarg, &pid_filter, INT_MAX, true)) goto usage; break;
        case 'P': pretty = true; break;
        case 'H': histogram = true; break;
        case 'b': if (strcmp(scene, "io") || threshold(optarg, &baseline_io_us)) goto usage; break;
        case 'f': if (strcmp(scene, "mem") || threshold(optarg, &baseline_faults)) goto usage; break;
        case 'n': if (strcmp(scene, "lock") || positive(optarg, &min_waiters, 16384, false)) goto usage; break;
        case 'w': if (strcmp(scene, "lock") || threshold(optarg, &wait_ms)) goto usage; break;
        case 'h': result = 0; goto usage;
        default: goto usage;
        }
    }
    if (optind != argc) goto usage;
    if (strcmp(path, "-")) { out = fopen(path, "a"); if (!out) { perror(path); goto done; } }
    signal(SIGINT, monitor_signal); signal(SIGTERM, monitor_signal); signal(SIGPIPE, SIG_IGN);
    rows = calloc(P2_ROWS, sizeof(*rows)); previous = calloc(P2_ROWS, sizeof(*previous));
    if (!rows || !previous) { perror("calloc"); goto done; }
    if (!strcmp(scene, "io")) {
        io = io_latency_bpf__open(); if (!io) goto done;
        io->rodata->target_pid = pid_filter;
        if (io_latency_bpf__load(io) || io_latency_bpf__attach(io)) goto done;
        event_fd = bpf_map__fd(io->maps.events); callback = io_event;
    } else if (!strcmp(scene, "mem")) {
        mem = mem_pressure_bpf__open(); if (!mem) goto done;
        mem->rodata->target_pid = pid_filter; mem->rodata->ignored_pid = getpid();
        cpus = libbpf_num_possible_cpus(); if (cpus <= 0) goto done;
        if (mem_pressure_bpf__load(mem) || mem_pressure_bpf__attach(mem)) goto done;
        event_fd = bpf_map__fd(mem->maps.events); callback = oom_event;
    } else {
        lock = lock_contention_bpf__open(); if (!lock) goto done;
        lock->rodata->target_pid = pid_filter; lock->rodata->ignored_pid = getpid();
        if (lock_contention_bpf__load(lock) || lock_contention_bpf__attach(lock)) goto done;
        event_fd = bpf_map__fd(lock->maps.events); callback = lock_event;
    }
    ring = ring_buffer__new(event_fd, callback, NULL, NULL); if (!ring) goto done;
    fprintf(stderr, "%s 已启动；场景 %s，窗口 %u 秒，pid=%u。\n", OSMEDIC_NAME, scene, interval, pid_filter);
    unsigned long long begin = monitor_now_ns(CLOCK_MONOTONIC), last = begin;
    unsigned long long deadline = duration ? begin + (unsigned long long)duration * 1000000000ULL : ULLONG_MAX;
    monitor_timestamp(start, sizeof(start));
    memcpy(end, start, sizeof(end));
    while (true) {
        int err = ring_buffer__poll(ring, 50);
        if (err < 0 && err != -EINTR) { fprintf(stderr, "ringbuf 读取失败: %s\n", strerror(-err)); goto done; }
        now_ns = monitor_now_ns(CLOCK_MONOTONIC);
        if (now_ns >= last + (unsigned long long)interval * 1000000000ULL || now_ns >= deadline || monitor_stop) {
            monitor_timestamp(end, sizeof(end));
            if (now_ns > last && emit_window((now_ns - last) / 1e9)) { perror("输出/快照失败"); goto done; }
            last = now_ns; memcpy(start, end, sizeof(start));
        }
        if (now_ns >= deadline || monitor_stop) break;
    }
    result = 0;
    goto done;
usage:
    fprintf(stderr, "%s [--duration SEC] [--interval SEC] [--pid PID] [--output FILE|-] [--pretty] [--histogram]\nIO: --baseline-p99-us US; MEM: --baseline-faults RATE; LOCK: --min-waiters N --wait-ms MS\n", OSMEDIC_NAME);
done:
    ring_buffer__free(ring);
    io_latency_bpf__destroy(io); mem_pressure_bpf__destroy(mem); lock_contention_bpf__destroy(lock);
    free(rows); free(previous);
    if (out && out != stdout && fclose(out)) result = 1;
    else if (out == stdout && fflush(out)) result = 1;
    return result;
}
