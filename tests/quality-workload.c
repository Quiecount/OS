#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>

static const char *mode;
static int threads, duty, pipefd[2];
static unsigned long long finish, start, rate, count[16];
static unsigned long long wall_samples[4096], cpu_samples[4096];
static int samples;
static unsigned long long ns(clockid_t clock)
{
    struct timespec t; clock_gettime(clock, &t);
    return (unsigned long long)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static void until(unsigned long long deadline)
{
    struct timespec t = {deadline / 1000000000ULL, deadline % 1000000000ULL};
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t, NULL);
}
static void *writer(void *arg)
{
    (void)arg;
    while (ns(CLOCK_MONOTONIC) < finish) {
        until(ns(CLOCK_MONOTONIC) + 20000000ULL);
        if (write(pipefd[1], "x", 1) != 1) break;
    }
    close(pipefd[1]);
    return NULL;
}
static void *sample_cpu(void *arg)
{
    (void)arg;
    while (ns(CLOCK_MONOTONIC) < finish && samples < 4096) {
        wall_samples[samples] = ns(CLOCK_MONOTONIC);
        cpu_samples[samples++] = ns(CLOCK_PROCESS_CPUTIME_ID);
        until(ns(CLOCK_MONOTONIC) + 10000000ULL);
    }
    return NULL;
}
static void *worker(void *arg)
{
    unsigned int index = (unsigned long)arg;
    struct stat st;
    unsigned long long next_period = start;
    while (ns(CLOCK_MONOTONIC) < finish) {
        if (!strcmp(mode, "cpu")) {
            unsigned long long busy_end = next_period + duty * 100000ULL;
            while (ns(CLOCK_MONOTONIC) < busy_end) __asm__ volatile("" ::: "memory");
            next_period += 10000000ULL;
            if (duty < 100) until(next_period);
        } else if (!strcmp(mode, "sleep")) {
            struct timespec delay = {0, 20000000};
            syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &delay, NULL);
            count[index]++;
        } else if (!strcmp(mode, "read")) {
            char c;
            if (syscall(SYS_read, pipefd[0], &c, 1) <= 0) break;
            count[index]++;
        } else {
            if (!strcmp(mode, "getpid")) syscall(SYS_getpid);
            else if (!strcmp(mode, "stat")) syscall(SYS_newfstatat, AT_FDCWD, "/dev/null", &st, 0);
            else {
                int fd = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY, 0);
                if (fd < 0) return (void *)1;
                syscall(SYS_close, fd);
            }
            count[index]++;
            if (rate && count[index] % 32 == 0)
                until(start + count[index] * threads * 1000000000ULL / rate);
        }
    }
    return NULL;
}
int main(int argc, char **argv)
{
    if (argc != 6) return 2;
    mode = argv[1]; double seconds = atof(argv[2]); threads = atoi(argv[3]);
    rate = strtoull(argv[4], NULL, 10); duty = atoi(argv[5]);
    if (seconds <= 0 || seconds > 3600 || threads < 1 || threads > 16 || duty < 0 || duty > 100) return 2;
    if (!strcmp(mode, "read") && threads != 1) return 2;
    if (!strcmp(mode, "read") && pipe(pipefd)) return 3;
    printf("{\"pid\":%d,\"getpid\":%d,\"stat\":%d,\"open\":%d,\"close\":%d,\"sleep\":%d,\"read\":%d}\n",
           getpid(), SYS_getpid, SYS_newfstatat, SYS_openat, SYS_close, SYS_clock_nanosleep, SYS_read);
    fflush(stdout);
    if (getchar() == EOF) return 3;
    start = ns(CLOCK_MONOTONIC); finish = start + seconds * 1000000000.0;
    unsigned long long cpu_start = ns(CLOCK_PROCESS_CPUTIME_ID);
    pthread_t workers[16], helper;
    int helper_kind = !strcmp(mode, "read") ? 1 : (!strcmp(mode, "cpu") ? 2 : 0);
    if (helper_kind && pthread_create(&helper, NULL, helper_kind == 1 ? writer : sample_cpu, NULL)) return 4;
    for (int i = 0; i < threads; ++i)
        if (pthread_create(&workers[i], NULL, worker, (void *)(unsigned long)i)) return 4;
    for (int i = 0; i < threads; ++i) {
        void *result;
        if (pthread_join(workers[i], &result) || result) return 5;
    }
    if (helper_kind) pthread_join(helper, NULL);
    unsigned long long end = ns(CLOCK_MONOTONIC), total = 0;
    for (int i = 0; i < threads; ++i) total += count[i];
    printf("{\"start_ns\":%llu,\"end_ns\":%llu,\"cpu_ns\":%llu,\"calls\":%llu,\"cpu_samples\":[",
           start, end, ns(CLOCK_PROCESS_CPUTIME_ID) - cpu_start, total);
    for (int i = 0; i < samples; ++i)
        printf("%s[%llu,%llu]", i ? "," : "", wall_samples[i], cpu_samples[i]);
    puts("]}");
    return 0;
}
