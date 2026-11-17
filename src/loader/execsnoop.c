#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bpf/libbpf.h>

#include "execsnoop.skel.h"
#include "osmedic.h"

static volatile sig_atomic_t stop;
static FILE *output;
static uint64_t realtime_offset_ns;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stop = 1;
}

static uint64_t clock_ns(clockid_t clock_id)
{
    struct timespec value;

    if (clock_gettime(clock_id, &value) != 0)
        return 0;
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static void format_timestamp(uint64_t timestamp_ns, char *buffer, size_t size)
{
    time_t seconds = (time_t)(timestamp_ns / 1000000000ULL);
    unsigned int milliseconds = (timestamp_ns % 1000000000ULL) / 1000000ULL;
    struct tm utc;
    char base[32];

    gmtime_r(&seconds, &utc);
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &utc);
    snprintf(buffer, size, "%s.%03uZ", base, milliseconds);
}

static void write_json_string(FILE *stream, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;

    fputc('"', stream);
    while (*cursor) {
        switch (*cursor) {
        case '"':
            fputs("\\\"", stream);
            break;
        case '\\':
            fputs("\\\\", stream);
            break;
        case '\b':
            fputs("\\b", stream);
            break;
        case '\f':
            fputs("\\f", stream);
            break;
        case '\n':
            fputs("\\n", stream);
            break;
        case '\r':
            fputs("\\r", stream);
            break;
        case '\t':
            fputs("\\t", stream);
            break;
        default:
            if (*cursor < 0x20)
                fprintf(stream, "\\u%04x", *cursor);
            else
                fputc(*cursor, stream);
        }
        cursor++;
    }
    fputc('"', stream);
}

static int handle_event(void *context, void *data, size_t data_size)
{
    const struct exec_event *event = data;
    char timestamp[48];

    (void)context;
    if (data_size < sizeof(*event))
        return 0;

    format_timestamp(realtime_offset_ns + event->ktime_ns, timestamp,
                     sizeof(timestamp));
    fputs("{\"schema_version\":1,\"event\":\"process_exec\",\"timestamp\":", output);
    write_json_string(output, timestamp);
    fprintf(output, ",\"ktime_ns\":%llu,\"pid\":%u,\"tid\":%u,\"uid\":%u,\"comm\":",
            event->ktime_ns, event->pid, event->tid, event->uid);
    write_json_string(output, event->comm);
    fputs(",\"filename\":", output);
    write_json_string(output, event->filename);
    fputs("}\n", output);
    fflush(output);
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "用法: %s [-o FILE|-] [-d SECONDS]\n"
            "  -o, --output FILE     JSONL 输出文件，- 表示标准输出（默认）\n"
            "  -d, --duration SEC    运行秒数，0 表示持续运行（默认）\n",
            program);
}

int main(int argc, char **argv)
{
    const struct option options[] = {
        {"output", required_argument, NULL, 'o'},
        {"duration", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };
    const char *output_path = "-";
    unsigned long duration = 0;
    struct execsnoop_bpf *skeleton = NULL;
    struct ring_buffer *ring = NULL;
    uint64_t deadline_ns = 0;
    int option;
    int result = 1;

    while ((option = getopt_long(argc, argv, "o:d:h", options, NULL)) != -1) {
        switch (option) {
        case 'o':
            output_path = optarg;
            break;
        case 'd':
            duration = strtoul(optarg, NULL, 10);
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }

    output = stdout;
    if (strcmp(output_path, "-") != 0) {
        output = fopen(output_path, "a");
        if (!output) {
            fprintf(stderr, "无法打开输出文件 %s: %s\n", output_path, strerror(errno));
            return 1;
        }
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    realtime_offset_ns = clock_ns(CLOCK_REALTIME) - clock_ns(CLOCK_MONOTONIC);
    if (duration > 0)
        deadline_ns = clock_ns(CLOCK_MONOTONIC) + duration * 1000000000ULL;

    skeleton = execsnoop_bpf__open_and_load();
    if (!skeleton) {
        fprintf(stderr, "加载 execsnoop BPF 对象失败；请使用 root 或授予 CAP_BPF/CAP_PERFMON。\n");
        goto cleanup;
    }
    if (execsnoop_bpf__attach(skeleton) != 0) {
        fprintf(stderr, "挂载 execve tracepoint 失败。\n");
        goto cleanup;
    }

    ring = ring_buffer__new(bpf_map__fd(skeleton->maps.events), handle_event,
                            NULL, NULL);
    if (!ring) {
        fprintf(stderr, "创建 ring buffer 读取器失败。\n");
        goto cleanup;
    }

    fprintf(stderr, "execsnoop 已启动，JSONL 输出到 %s。按 Ctrl-C 停止。\n", output_path);
    while (!stop) {
        int poll_result = ring_buffer__poll(ring, 200);
        if (poll_result == -EINTR)
            break;
        if (poll_result < 0) {
            fprintf(stderr, "ring buffer 轮询失败: %d\n", poll_result);
            goto cleanup;
        }
        if (deadline_ns && clock_ns(CLOCK_MONOTONIC) >= deadline_ns)
            break;
    }
    result = 0;

cleanup:
    ring_buffer__free(ring);
    execsnoop_bpf__destroy(skeleton);
    if (output && output != stdout)
        fclose(output);
    return result;
}
