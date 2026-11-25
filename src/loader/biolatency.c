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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "biolatency.skel.h"
#include "osmedic.h"

#define MAX_DEVICES 128

struct device_histogram {
    bool used;
    unsigned int major;
    unsigned int minor;
    char disk[OSMEDIC_DISK_LEN];
    unsigned long long buckets[OSMEDIC_HIST_SLOTS];
};

static volatile sig_atomic_t stop;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stop = 1;
}

static uint64_t monotonic_ns(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0;
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static void sleep_milliseconds(long milliseconds)
{
    struct timespec delay = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (milliseconds % 1000) * 1000000L,
    };

    while (nanosleep(&delay, &delay) != 0 && errno == EINTR && !stop)
        ;
}

static void format_now(char *buffer, size_t size)
{
    struct timespec now;
    struct tm utc;
    char base[32];

    clock_gettime(CLOCK_REALTIME, &now);
    gmtime_r(&now.tv_sec, &utc);
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &utc);
    snprintf(buffer, size, "%s.%03ldZ", base, now.tv_nsec / 1000000L);
}

static struct device_histogram *find_device(struct device_histogram *devices,
                                             const struct io_hist_key *key)
{
    struct device_histogram *empty = NULL;

    for (size_t i = 0; i < MAX_DEVICES; i++) {
        if (devices[i].used && devices[i].major == key->major &&
            devices[i].minor == key->minor &&
            strncmp(devices[i].disk, key->disk, sizeof(devices[i].disk)) == 0)
            return &devices[i];
        if (!devices[i].used && !empty)
            empty = &devices[i];
    }
    if (empty) {
        empty->used = true;
        empty->major = key->major;
        empty->minor = key->minor;
        snprintf(empty->disk, sizeof(empty->disk), "%s", key->disk);
    }
    return empty;
}

static int emit_histograms(int map_fd, FILE *output, unsigned int window_seconds)
{
    struct device_histogram devices[MAX_DEVICES] = {};
    struct io_hist_key key;
    struct io_hist_key next_key;
    bool have_key = false;
    unsigned long long count;
    char timestamp[48];
    int result;

    while ((result = bpf_map_get_next_key(map_fd, have_key ? &key : NULL,
                                          &next_key)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &count) == 0) {
            struct device_histogram *device = find_device(devices, &next_key);
            if (device && next_key.slot < OSMEDIC_HIST_SLOTS)
                device->buckets[next_key.slot] += count;
        }
        bpf_map_delete_elem(map_fd, &next_key);
        key = next_key;
        have_key = true;
    }
    if (result != -ENOENT) {
        fprintf(stderr, "遍历 histogram map 失败: %s\n", strerror(errno));
        return -1;
    }

    format_now(timestamp, sizeof(timestamp));
    for (size_t i = 0; i < MAX_DEVICES; i++) {
        unsigned long long total = 0;

        if (!devices[i].used)
            continue;
        for (unsigned int slot = 0; slot < OSMEDIC_HIST_SLOTS; slot++)
            total += devices[i].buckets[slot];
        if (total == 0)
            continue;

        fprintf(output,
                "{\"schema_version\":1,\"event\":\"block_io_latency_histogram\","
                "\"timestamp\":\"%s\",\"window_seconds\":%u,\"device\":\"%s\","
                "\"major\":%u,\"minor\":%u,\"samples\":%llu,\"buckets\":[",
                timestamp, window_seconds, devices[i].disk, devices[i].major,
                devices[i].minor, total);
        for (unsigned int slot = 0; slot < OSMEDIC_HIST_SLOTS; slot++) {
            unsigned long long upper_us = 1ULL << slot;
            fprintf(output,
                    "%s{\"upper_us\":%llu,\"count\":%llu}",
                    slot ? "," : "", upper_us, devices[i].buckets[slot]);
        }
        fputs("]}\n", output);
    }
    fflush(output);
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "用法: %s [-o FILE|-] [-i SECONDS] [-d SECONDS]\n"
            "  -o, --output FILE     JSONL 输出文件，- 表示标准输出（默认）\n"
            "  -i, --interval SEC    直方图输出窗口（默认 5 秒）\n"
            "  -d, --duration SEC    总运行秒数，0 表示持续运行（默认）\n",
            program);
}

int main(int argc, char **argv)
{
    const struct option options[] = {
        {"output", required_argument, NULL, 'o'},
        {"interval", required_argument, NULL, 'i'},
        {"duration", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };
    const char *output_path = "-";
    unsigned int interval = 5;
    unsigned long duration = 0;
    struct biolatency_bpf *skeleton = NULL;
    uint64_t started_ns;
    uint64_t next_emit_ns;
    FILE *output = stdout;
    int option;
    int result = 1;

    while ((option = getopt_long(argc, argv, "o:i:d:h", options, NULL)) != -1) {
        switch (option) {
        case 'o':
            output_path = optarg;
            break;
        case 'i':
            interval = strtoul(optarg, NULL, 10);
            if (interval == 0)
                interval = 1;
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

    if (strcmp(output_path, "-") != 0) {
        output = fopen(output_path, "a");
        if (!output) {
            fprintf(stderr, "无法打开输出文件 %s: %s\n", output_path, strerror(errno));
            return 1;
        }
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skeleton = biolatency_bpf__open_and_load();
    if (!skeleton) {
        fprintf(stderr, "加载 biolatency BPF 对象失败；请使用 root 或授予 CAP_BPF/CAP_PERFMON。\n");
        goto cleanup;
    }
    if (biolatency_bpf__attach(skeleton) != 0) {
        fprintf(stderr, "挂载 block_rq_issue/complete raw tracepoint 失败。\n");
        goto cleanup;
    }

    fprintf(stderr, "biolatency 已启动，每 %u 秒输出一次 JSONL 直方图。按 Ctrl-C 停止。\n",
            interval);
    started_ns = monotonic_ns();
    next_emit_ns = started_ns + (uint64_t)interval * 1000000000ULL;
    while (!stop) {
        uint64_t now = monotonic_ns();

        if (duration > 0 && now - started_ns >= duration * 1000000000ULL)
            break;
        if (now >= next_emit_ns) {
            if (emit_histograms(bpf_map__fd(skeleton->maps.histogram), output,
                                interval) != 0)
                goto cleanup;
            next_emit_ns += (uint64_t)interval * 1000000000ULL;
        }
        sleep_milliseconds(100);
    }
    if (emit_histograms(bpf_map__fd(skeleton->maps.histogram), output,
                        interval) != 0)
        goto cleanup;
    result = 0;

cleanup:
    biolatency_bpf__destroy(skeleton);
    if (output && output != stdout)
        fclose(output);
    return result;
}
