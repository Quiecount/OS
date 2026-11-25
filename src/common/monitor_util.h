#ifndef OSMEDIC_MONITOR_UTIL_H
#define OSMEDIC_MONITOR_UTIL_H

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "latency_hist.h"

static volatile sig_atomic_t monitor_stop;

static void monitor_signal(int signum)
{
    (void)signum;
    monitor_stop = 1;
}

static uint64_t monitor_now_ns(clockid_t which)
{
    struct timespec ts;
    if (clock_gettime(which, &ts))
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void monitor_timestamp(char *out, size_t size)
{
    struct timespec ts;
    struct tm tm;
    char base[32];
    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm);
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out, size, "%s.%03ldZ", base, ts.tv_nsec / 1000000);
}

static void monitor_json_string(FILE *out, const char *s)
{
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            fputc('\\', out);
            fputc(*p, out);
        } else if (*p < 0x20) {
            fprintf(out, "\\u%04x", *p);
        } else {
            fputc(*p, out);
        }
    }
    fputc('"', out);
}

static void monitor_wait_until(uint64_t deadline_ns)
{
    while (!monitor_stop) {
        uint64_t now = monitor_now_ns(CLOCK_MONOTONIC);
        if (now >= deadline_ns)
            break;
        uint64_t left = deadline_ns - now;
        struct timespec delay = {
            .tv_sec = left / 1000000000ULL,
            .tv_nsec = left % 1000000000ULL,
        };
        if (nanosleep(&delay, &delay) != 0 && errno != EINTR)
            break;
    }
}

static unsigned long long monitor_p99(const unsigned long long *buckets,
                                       unsigned int slots,
                                       unsigned long long samples)
{
    if (!samples)
        return 0;
    unsigned long long target = (samples * 99 + 99) / 100;
    unsigned long long seen = 0;
    for (unsigned int i = 0; i < slots; ++i) {
        seen += buckets[i];
        if (seen >= target)
            return (latency_upper_ns(i) + 999) / 1000;
    }
    return 0;
}

#endif
